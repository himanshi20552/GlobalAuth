
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
