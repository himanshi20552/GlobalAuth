using System.Security.Cryptography;
using GlobalAuth.Client.Configuration;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace GlobalAuth.Client.DependencyInjection
{
    public static class GlobalAuthServiceCollectionExtensions
    {
        public static IServiceCollection AddGlobalAuthentication(this IServiceCollection services, Action<GlobalAuthOptions> configureOptions)
        {
            var options = new GlobalAuthOptions();
            configureOptions(options);
            if(string.IsNullOrWhiteSpace(options.Issuer))
				throw new InvalidOperationException("Issuer is required.");
            if(string.IsNullOrWhiteSpace(options.Audience))
                throw new InvalidOperationException("Audience is required.");
            if(string.IsNullOrWhiteSpace(options.PublicKeyPath))
				throw new InvalidOperationException("PublicKeyPath is required.");
            if(!File.Exists(options.PublicKeyPath))
				throw new FileNotFoundException("Public key file not found",options.PublicKeyPath);
            var rsa = RSA.Create();
            try{ rsa.ImportFromPem(File.ReadAllText(options.PublicKeyPath));
                var signingKey=new RsaSecurityKey(rsa){ KeyId = options.KeyId };
                services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
					.AddJwtBearer(jwtOptions =>
					{
						jwtOptions.MapInboundClaims = false;
						jwtOptions.TokenValidationParameters = new TokenValidationParameters
						{
							ValidateIssuerSigningKey = true,
							IssuerSigningKey = signingKey,
							ValidateIssuer = true,
							ValidIssuer = options.Issuer,
							ValidateAudience = true,
							ValidAudience = options.Audience,
							ValidateLifetime = true,
							ClockSkew = TimeSpan.FromMinutes(1),
							NameClaimType = "sub",
							RoleClaimType = "role"
						};
					});
				services.AddAuthorization();
				services.AddSingleton<IDisposable>(rsa);
				return services;
			}
			catch
			{
				rsa.Dispose();
				throw;
			}

		}
    }
}
