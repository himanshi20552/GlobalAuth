using GlobalAuth.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace GlobalAuth.Api.Controllers
{
    [ApiController]
    [AllowAnonymous]
    [Route(".well-known")]
    public sealed class JwksController : ControllerBase
    {
        private readonly ISigningKeyProvider _signingKeyProvider;
        public JwksController(ISigningKeyProvider signingKeyProvider) {
            _signingKeyProvider = signingKeyProvider;
        }
        [HttpGet("jwks.json")]
        public IActionResult GetJwks()
        {
            var signingCredentials = _signingKeyProvider.GetSigningCredentials();
            if (signingCredentials.Key is not RsaSecurityKey rsaSecurityKey) {
                throw new InvalidOperationException("The configured signing key must be a RSA key.");
            }
            var parameters = rsaSecurityKey.Rsa is not null ? rsaSecurityKey.Rsa.ExportParameters(false) :
                rsaSecurityKey.Parameters;
            if (parameters.Modulus is null || parameters.Exponent is null)
            {
                throw new InvalidOperationException("RSA public key parameters are unavailable");
                
            }
            var jwk = new
            {
                kty = "RSA",
                use = "sig",
                alg = SecurityAlgorithms.RsaSha256,
                kid = rsaSecurityKey.KeyId,
                n = Base64UrlEncoder.Encode(parameters.Modulus),
                e = Base64UrlEncoder.Encode(parameters.Exponent)
            };
            Response.Headers.CacheControl = "public,max-age=3600";
            return Ok(new
            {
                keys = new[] { jwk }
            });
        }
    }
}
