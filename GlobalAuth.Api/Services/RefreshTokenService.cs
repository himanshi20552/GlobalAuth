using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace GlobalAuth.Api.Services
{
    public sealed class RefreshTokenService
    {
        public (string Token, byte[] TokenHash) Generate()
        {
            var randomBytes = RandomNumberGenerator.GetBytes(32);
			var token = WebEncoders.Base64UrlEncode(randomBytes);
            var tokenHash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
            return (token, tokenHash);
		}
		public byte[] ComputeHash(string token)
		{
			ArgumentException.ThrowIfNullOrWhiteSpace(token);
			return SHA256.HashData(Encoding.UTF8.GetBytes(token));
		}
	}
}
