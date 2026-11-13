using System.Security.Cryptography;
using System.Threading.RateLimiting;
using ApplicationAuthentication.Authentication.Interfaces;
using ApplicationAuthentication.Repositories.Interfaces;
using ApplicationAuthentication.Services;
using ApplicationAuthentication.Services.Interfaces;
using GlobalAuth.Api.Configuration;
using GlobalAuth.Api.Constants;
using GlobalAuth.Api.Data;
using GlobalAuth.Api.Repositories;
using GlobalAuth.Api.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using UserAuthRepositories = ApplicationAuthentication.Repositories;
using UserAuthServices = ApplicationAuthentication.Services;

var builder = WebApplication.CreateBuilder(args);

// Controllers and OpenAPI
builder.Services.AddControllers();

builder.Services.AddRateLimiter(options =>
{
	options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

	// for client token generation
	options.AddPolicy("ClientTokenLimit", httpContext =>
		RateLimitPartition.GetFixedWindowLimiter(
			httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
			_ => new FixedWindowRateLimiterOptions
			{
				PermitLimit = 10,
				Window = TimeSpan.FromMinutes(1),
				QueueLimit = 0,
				AutoReplenishment = true
			}));

	// for refresh and logout
	options.AddPolicy("TokenOperationsLimit", httpContext =>
		RateLimitPartition.GetFixedWindowLimiter(
			httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
			_ => new FixedWindowRateLimiterOptions
			{
				PermitLimit = 30,
				Window = TimeSpan.FromMinutes(1),
				QueueLimit = 0,
				AutoReplenishment = true
			}));
});

builder.Services.AddOpenApi();

// Database
builder.Services.AddSingleton<SqlConnectionFactory>();

// Configuration
builder.Services.Configure<JwtOptions>(
	builder.Configuration.GetSection("Jwt"));

builder.Services.Configure<RefreshTokenOptions>(
	builder.Configuration.GetSection("RefreshToken"));

// token services
builder.Services.AddScoped<ITokenService, JwtTokenService>();
builder.Services.AddScoped<ITokenIssuanceService, TokenIssuanceService>();
builder.Services.AddScoped<TokenRefreshService>();
builder.Services.AddSingleton<RefreshTokenService>();

// session and authentication services
builder.Services.AddScoped<SessionService>();
builder.Services.AddScoped<ClientAuthenticationService>();
builder.Services.AddScoped<ClientManagementService>();

// repos
builder.Services.AddScoped<AuthSessionRepository>();
builder.Services.AddScoped<AuthRefreshTokenRepository>();
builder.Services.AddScoped<AuthTokenIssuanceAuditRepository>();
builder.Services.AddScoped<ClientCredentialRepository>();
builder.Services.AddScoped<ClientPermissionRepository>();
builder.Services.AddScoped<ApplicationRepository>();
builder.Services.AddScoped<ClientRefreshTokenRepository>();

// User authentication repositories
builder.Services.AddScoped<IUserRepository, UserAuthRepositories.UserRepository>();
builder.Services.AddScoped<IGroupRepository, UserAuthRepositories.GroupRepository>();
builder.Services.AddScoped<IPermissionRepository, UserAuthRepositories.PermissionRepository>();
builder.Services.AddScoped<IUserApplicationRepository, UserAuthRepositories.UserApplicationRepository>();

builder.Services.AddScoped<IApplicationRepository, UserAuthRepositories.ApplicationRepository>();

// User authentication services
builder.Services.AddScoped<IPasswordHashingService, UserAuthServices.PasswordHashingService>();
builder.Services.AddScoped<IAuthenticationService, UserAuthServices.AuthenticationService>();
builder.Services.AddScoped<IPasswordChangeService,PasswordChangeService>();
builder.Services.AddScoped<ApplicationService>();
builder.Services.AddScoped<IApplicationValidationService, UserAuthServices.ApplicationValidationService>();
builder.Services.AddScoped<IUserApplicationAccessService, UserAuthServices.UserApplicationAccessService>();

// Shared authorization provider
builder.Services.AddScoped<GlobalAuth.Api.Services.IUserAuthorizationProvider, UserAuthServices.UserAuthorizationProvider>();
// rsa signing key provider
builder.Services.AddSingleton<ISigningKeyProvider, RsaFileSigningKeyProvider>();
// jwt Bearer authentication
builder.Services
	.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
	.AddJwtBearer();

builder.Services
	.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
	.Configure<ISigningKeyProvider, IOptions<JwtOptions>>(
		(jwtOptions, signingKeyProvider, jwtOptionsAccessor) =>
		{
			var jwtSettings = jwtOptionsAccessor.Value;
			var signingKey = signingKeyProvider
				.GetSigningCredentials()
				.Key as RsaSecurityKey
				?? throw new InvalidOperationException(
					"RSA signing key is required.");
			// Create a separate RSA instance containing only
			// the public key parameters.
			var publicRsa = RSA.Create();

			var publicParameters = signingKey.Rsa!.ExportParameters(false);
			publicRsa.ImportParameters(publicParameters);
			var validationKey = new RsaSecurityKey(publicRsa)
			{
				KeyId = jwtSettings.KeyId
			};

			jwtOptions.MapInboundClaims = false;
			jwtOptions.TokenValidationParameters =
				new TokenValidationParameters
				{
					ValidateIssuerSigningKey = true,
					IssuerSigningKey = validationKey,
					ValidateIssuer = true,
					ValidIssuer = jwtSettings.Issuer,
					ValidateAudience = true,
					ValidAudience = jwtSettings.Audience,
					ValidateLifetime = true,
					ClockSkew = TimeSpan.FromMinutes(1),

					ValidAlgorithms = new[]
					{SecurityAlgorithms.RsaSha256},

					ValidTypes = new[]
					{"at+jwt"},
					NameClaimType = "sub",
					RoleClaimType = "role"
				};

			jwtOptions.Events = new JwtBearerEvents
			{

				OnTokenValidated = context =>
				{
					var principal = context.Principal;

					if (principal is null)
					{
						context.Fail("Missing token principal.");
						return Task.CompletedTask;
					}

					// Claims required for both USER and CLIENT tokens.
					string[] requiredClaims =
					{
		"sub",
		"jti",
		"principal_type",
		"token_type",
		"client_id"
	};

					foreach (var claimType in requiredClaims)
					{
						var claims = principal.FindAll(claimType).ToArray();

						if (claims.Length != 1 ||
							string.IsNullOrWhiteSpace(claims[0].Value))
						{
							context.Fail($"Invalid or missing {claimType} claim.");
							return Task.CompletedTask;
						}
					}

					var principalType = principal.FindFirst("principal_type")!.Value;
					var tokenType = principal.FindFirst("token_type")!.Value;

					if (principalType != "USER" && principalType != "CLIENT")
					{
						context.Fail("Invalid principal type.");
						return Task.CompletedTask;
					}

					if (tokenType != "access")
					{
						context.Fail("Invalid token type.");
						return Task.CompletedTask;
					}

					// Only USER tokens should contain a session ID.
					var sessionClaims = principal.FindAll("sid").ToArray();

					if (principalType == "USER")
					{
						if (sessionClaims.Length != 1 ||
							!Guid.TryParse(sessionClaims[0].Value, out _))
						{
							context.Fail("Invalid or missing session ID.");
							return Task.CompletedTask;
						}
					}
					else if (sessionClaims.Length != 0)
					{
						context.Fail("CLIENT tokens must not contain a session ID.");
						return Task.CompletedTask;
					}

					return Task.CompletedTask;
				}

			};
		});
builder.Services.AddAuthorization(options =>
{
	options.AddPolicy("ApplicationUpdate", policy =>
	{
		policy.RequireAuthenticatedUser();
		policy.RequireClaim(
			GlobalAuthClaimTypes.PrincipalType, "USER");
		policy.RequireClaim(
			GlobalAuthClaimTypes.ClientId, "AUTH_PLATFORM_ADMIN");
		policy.RequireClaim(
			GlobalAuthClaimTypes.Permission, "application.update");
	});

	options.AddPolicy("ApplicationDeactivate", policy =>
	{
		policy.RequireAuthenticatedUser();
		policy.RequireClaim(
			GlobalAuthClaimTypes.PrincipalType, "USER");
		policy.RequireClaim(
			GlobalAuthClaimTypes.ClientId, "AUTH_PLATFORM_ADMIN");
		policy.RequireClaim(
			GlobalAuthClaimTypes.Permission, "application.deactivate");
	});

	options.AddPolicy("ClientUpdate", policy =>
	{
		policy.RequireAuthenticatedUser();

		policy.RequireClaim(
			GlobalAuthClaimTypes.PrincipalType, "USER");

		policy.RequireClaim(
			GlobalAuthClaimTypes.ClientId, "AUTH_PLATFORM_ADMIN");

		policy.RequireClaim(
			GlobalAuthClaimTypes.Permission, "client.update");
	});

	options.AddPolicy("ClientDeactivate", policy =>
	{
		policy.RequireAuthenticatedUser();

		policy.RequireClaim(
			GlobalAuthClaimTypes.PrincipalType, "USER");

		policy.RequireClaim(
			GlobalAuthClaimTypes.ClientId, "AUTH_PLATFORM_ADMIN");

		policy.RequireClaim(
			GlobalAuthClaimTypes.Permission, "client.deactivate");
	});

	options.AddPolicy("ClientSecretRotate", policy =>
	{
		policy.RequireAuthenticatedUser();

		policy.RequireClaim(
			GlobalAuthClaimTypes.PrincipalType, "USER");

		policy.RequireClaim(
			GlobalAuthClaimTypes.ClientId, "AUTH_PLATFORM_ADMIN");

		policy.RequireClaim(
			GlobalAuthClaimTypes.Permission, "client.secret.rotate");
	});

});
// Build application
var app = builder.Build();

if (app.Environment.IsDevelopment())
{
	app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseRouting();
app.UseRateLimiter();

// Authentication must run before authorization.
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
