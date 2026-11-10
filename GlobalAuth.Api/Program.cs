
using System.Security.Cryptography;
using GlobalAuth.Api.Configuration;
using GlobalAuth.Api.Services;
using GlobalAuth.Api.Data;
using GlobalAuth.Api.Repositories;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// Controllers and OpenAPI
builder.Services.AddControllers();

builder.Services.AddRateLimiter(options =>
{
	options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

	// Client token generation: 10 requests per minute per IP.
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

	// Refresh and logout: 30 requests per minute per IP.
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

// rsa signing key provider
builder.Services.AddSingleton<ISigningKeyProvider, RsaFileSigningKeyProvider>();

// jwt Bearer authentication
builder.Services
	.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
	.AddJwtBearer();

builder.Services
	.AddOptions<JwtBearerOptions>(
		JwtBearerDefaults.AuthenticationScheme)
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
					{
						SecurityAlgorithms.RsaSha256
					},

					ValidTypes = new[]
					{
						"at+jwt"
					},

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

					string[] requiredClaims =
					{
						"sub",
						"jti",
						"sid",
						"principal_type",
						"token_type"
					};

					foreach (var claimType in requiredClaims)
					{
						var claims = principal.FindAll(claimType).ToArray();

						if (claims.Length != 1 ||
							string.IsNullOrWhiteSpace(claims[0].Value))
						{
							context.Fail(
								$"Invalid or missing {claimType} claim.");

							return Task.CompletedTask;
						}
					}

					if (!Guid.TryParse(
						principal.FindFirst("sid")!.Value,
						out _))
					{
						context.Fail("Invalid session ID.");
						return Task.CompletedTask;
					}

					var principalType =
						principal.FindFirst("principal_type")!.Value;

					if (principalType != "USER" &&
						principalType != "CLIENT")
					{
						context.Fail("Invalid principal type.");
						return Task.CompletedTask;
					}

					var tokenType =
						principal.FindFirst("token_type")!.Value;

					if (tokenType != "access")
					{
						context.Fail("Invalid token type.");
						return Task.CompletedTask;
					}

					return Task.CompletedTask;
				}
			};
		});

builder.Services.AddAuthorization();

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
