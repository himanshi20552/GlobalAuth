using System.Security.Cryptography;
using GlobalAuth.Api.Configuration;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
namespace GlobalAuth.Api.Services
{
    public sealed class RsaFileSigningKeyProvider : ISigningKeyProvider,IDisposable
    {
        private readonly RSA _rsa;
        private readonly SigningCredentials _signingCredentials;
        public RsaFileSigningKeyProvider(IOptions<JwtOptions> options) {
            var settings = options.Value;
            string keyPath = settings.SigningKeyPath ?? Path.Combine(Environment.GetFolderPath(
                Environment.SpecialFolder.LocalApplicationData),
                "GlobalAuth", "keys", "jwt-private-key.pem");
            if(!File.Exists(keyPath))
			{
				throw new FileNotFoundException($"Signing key file not found at path: {keyPath}");
			}
            _rsa=RSA.Create();
            _rsa.ImportFromPem(File.ReadAllText(keyPath));
            if(_rsa.KeySize<2048)
			{
                _rsa.Dispose();
				throw new InvalidOperationException("RSA key size must be at least 2048 bits.");
			}
            var securityKey = new RsaSecurityKey(_rsa)
            {
                KeyId = settings.KeyId
            };
            _signingCredentials= new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha256);


		}
        public SigningCredentials GetSigningCredentials()
		{
			return _signingCredentials;
		}
        public void Dispose() {
            _rsa.Dispose();

        }

	}
}
