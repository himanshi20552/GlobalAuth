using GlobalAuth.Client.Authorization;
using GlobalAuth.Client.Configuration;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using GlobalAuth.Client.Services;
using Microsoft.Extensions.Logging;
namespace GlobalAuth.Client.DependencyInjection;

public static class GlobalAuthServiceCollectionExtensions
{
	public static IServiceCollection AddGlobalAuthentication(this IServiceCollection services,
		Action<GlobalAuthOptions> configureOptions)
	{
		ArgumentNullException.ThrowIfNull(configureOptions);

		var options = new GlobalAuthOptions();
		configureOptions(options);

		if (string.IsNullOrWhiteSpace(options.Issuer))
			throw new InvalidOperationException("Issuer is required.");

		if (string.IsNullOrWhiteSpace(options.Audience))
			throw new InvalidOperationException("Audience is required.");

		if (!Uri.TryCreate(
				options.Authority,
				UriKind.Absolute,
				out var authorityUri) ||
			authorityUri.Scheme != Uri.UriSchemeHttps)
		{
			throw new InvalidOperationException(
				"Authority must be a valid HTTPS URL.");
		}

		var authority = authorityUri.ToString().TrimEnd('/');

		if (!Uri.TryCreate(
				options.SessionValidationEndpoint,
				UriKind.Relative,
				out _))
		{
			throw new InvalidOperationException(
				"Session validation endpoint must be a relative URL.");
		}

		services.AddHttpClient("GlobalAuth", httpClient =>
		{
			httpClient.BaseAddress = new Uri(authority + "/");
		});

		services.AddTransient<SessionValidationClient>(serviceProvider =>
		{
			var httpClientFactory =
				serviceProvider.GetRequiredService<IHttpClientFactory>();

			var httpClient = httpClientFactory.CreateClient("GlobalAuth");

			return new SessionValidationClient(
				httpClient,
				options.SessionValidationEndpoint);
		});

		services.AddAuthentication(
			JwtBearerDefaults.AuthenticationScheme)
			.AddJwtBearer(jwtOptions =>
			{
				jwtOptions.Authority = authority;

				// Require HTTPS when retrieving authentication metadata.
				jwtOptions.RequireHttpsMetadata = true;

				// Refresh metadata when a token contains an unknown kid.
				jwtOptions.RefreshOnIssuerKeyNotFound = true;

				jwtOptions.MapInboundClaims = false;

				jwtOptions.TokenValidationParameters =
					new TokenValidationParameters
					{
						ValidateIssuerSigningKey = true,

						ValidateIssuer = true,
						ValidIssuer = options.Issuer,

						ValidateAudience = true,
						ValidAudience = options.Audience,
						RequireSignedTokens=true,
						RequireExpirationTime=true,

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
					OnTokenValidated = async context =>
					{
						var principal = context.Principal;

						if (principal is null)
						{
							context.Fail("Missing token principal.");
							return;
						}

						// Required claims for USER access tokens.
						string[] requiredClaims =
						{
			"sub",
			"jti",
			"sid",
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
								return;
							}
						}

						var principalType = principal.FindFirst("principal_type")!.Value;
						var tokenType = principal.FindFirst("token_type")!.Value;
						var sessionId = principal.FindFirst("sid")!.Value;

						// This library is intended for user applications.
						if (!string.Equals(
								principalType,
								"USER",
								StringComparison.OrdinalIgnoreCase))
						{
							context.Fail("Only USER tokens are supported.");
							return;
						}

						if (tokenType != "access")
						{
							context.Fail("Invalid token type.");
							return;
						}

						if (!Guid.TryParse(sessionId, out _))
						{
							context.Fail("Invalid session ID.");
							return;
						}

						// Extract the original bearer token.
						var authorizationHeader =
							context.Request.Headers.Authorization.ToString();

						const string bearerPrefix = "Bearer ";

						if (!authorizationHeader.StartsWith(
								bearerPrefix,
								StringComparison.OrdinalIgnoreCase))
						{
							context.Fail("Bearer token is missing.");
							return;
						}

						var accessToken =
							authorizationHeader[bearerPrefix.Length..].Trim();

						if (string.IsNullOrWhiteSpace(accessToken))
						{
							context.Fail("Bearer token is missing.");
							return;
						}

						// Ask GlobalAuth to validate the session.
						var sessionValidator = context.HttpContext.RequestServices
							.GetRequiredService<SessionValidationClient>();

						var loggerFactory = context.HttpContext.RequestServices
							.GetRequiredService<ILoggerFactory>();

						var logger = loggerFactory.CreateLogger(
							"GlobalAuth.Client.SessionValidation");

						try
						{
							var isSessionValid =
								await sessionValidator.ValidateSessionAsync(
									accessToken,
									context.HttpContext.RequestAborted);

							if (!isSessionValid)
							{
								context.Fail("User session is invalid or expired.");
								return;
							}
						}
						catch (OperationCanceledException)
							when (context.HttpContext.RequestAborted.IsCancellationRequested)
						{
							throw;
						}
						catch (Exception exception)
						{
							logger.LogError(
								exception,
								"GlobalAuth session validation could not be completed.");

							context.Fail("Session validation could not be completed.");
						}
					}
				};

			});

		services.AddAuthorization();

		services.AddScoped<
			IAuthorizationHandler,
			PermissionAuthorizationHandler>();

		return services;
	}
}
