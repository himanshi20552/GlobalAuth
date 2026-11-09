using System.Security.Cryptography;
using GlobalAuth.Client.Configuration;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using GlobalAuth.Client.Authorization;
using Microsoft.AspNetCore.Authorization;

namespace GlobalAuth.Client.DependencyInjection
{
	public static class GlobalAuthServiceCollectionExtensions
	{
		public static IServiceCollection AddGlobalAuthentication(
			this IServiceCollection services,
			Action<GlobalAuthOptions> configureOptions)
		{
			ArgumentNullException.ThrowIfNull(configureOptions);

			var options = new GlobalAuthOptions();
			configureOptions(options);

			if (string.IsNullOrWhiteSpace(options.Issuer))
				throw new InvalidOperationException("Issuer is required.");

			if (string.IsNullOrWhiteSpace(options.Audience))
				throw new InvalidOperationException("Audience is required.");

			if (string.IsNullOrWhiteSpace(options.PublicKeyPath))
				throw new InvalidOperationException("PublicKeyPath is required.");

			if (string.IsNullOrWhiteSpace(options.KeyId))
				throw new InvalidOperationException("KeyId is required.");

			if (!File.Exists(options.PublicKeyPath))
				throw new FileNotFoundException(
					"Public key file not found.",
					options.PublicKeyPath);

			var rsa = RSA.Create();

			try
			{
				rsa.ImportFromPem(File.ReadAllText(options.PublicKeyPath));

				if (rsa.KeySize < 2048)
					throw new InvalidOperationException(
						"RSA public key size must be at least 2048 bits.");

				var signingKey = new RsaSecurityKey(rsa)
				{
					KeyId = options.KeyId
				};

				services.AddSingleton<RSA>(_ => rsa);

				services.AddAuthentication(
					JwtBearerDefaults.AuthenticationScheme)
					.AddJwtBearer(jwtOptions =>
					{
						jwtOptions.MapInboundClaims = false;

						jwtOptions.TokenValidationParameters =
							new TokenValidationParameters
							{
								ValidateIssuerSigningKey = true,
								IssuerSigningKey = signingKey,

								ValidateIssuer = true,
								ValidIssuer = options.Issuer,

								ValidateAudience = true,
								ValidAudience = options.Audience,

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
								if (principal == null)
								{
									context.Fail("Missing token principal");
									return Task.CompletedTask;
								}
								string[] requiredClaims =
								{ "sub","jti","sid","principal_type","token_type" };
								foreach (var claimType in requiredClaims) {
									var claims = principal.FindAll(claimType).ToArray();
									if (claims.Length != 1 || string.IsNullOrWhiteSpace(claims[0].Value))
									{
										context.Fail($"Invalid or missing {claimType} claim.");
										return Task.CompletedTask;
									}
								}
								var sessionId = principal.FindFirst("sid")!.Value;
								if (!Guid.TryParse(sessionId, out _))
								{
									context.Fail("Invalid Session ID");
									return Task.CompletedTask;
								}
								var principalType = principal.FindFirst("principal_type")!.Value;
								if(!string.Equals(principalType,"USER",StringComparison.OrdinalIgnoreCase)&&
								!string.Equals(principalType, "CLIENT",StringComparison.OrdinalIgnoreCase))
								{
									context.Fail("Invalid principal type.");
									return Task.CompletedTask;
								}

								var tokenType = principal.FindFirst("token_type")!.Value;

								if (tokenType != "access")
								{
									context.Fail("Invalid token type.");
									return Task.CompletedTask;
								}

								return Task.CompletedTask;
							}
						};
					});
				services.AddAuthorization();
				services.AddScoped<IAuthorizationHandler, PermissionAuthorizationHandler>();
				return services;
			}
			catch
			{
				// If registration fails, the container will not own
				// this RSA instance, so dispose it here.
				rsa.Dispose();
				throw;
			}
		}
	}
}
