using GlobalAuth.Api.Configuration;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
namespace GlobalAuth.Api.Controllers
{
    [ApiController]
    [AllowAnonymous]
    [Route(".well-known")]
    public sealed class OpenIdConfigurationController : ControllerBase
    {
        private readonly JwtOptions _jwtOptions;
        public OpenIdConfigurationController(IOptions<JwtOptions> jwtOptions)
        {
            _jwtOptions = jwtOptions.Value;
        }
        [HttpGet("openid-configuration")]
        public IActionResult GetConfiguration()
        {
            if (string.IsNullOrWhiteSpace(_jwtOptions.PublicBaseUrl))
                    throw new InvalidOperationException("Jwt:PublicBaseUrl must be configured.");
            var baseUrl = _jwtOptions.PublicBaseUrl.TrimEnd('/');
            return Ok(new
            {
                issuer = _jwtOptions.Issuer,
                jwks_uri = $"{baseUrl}/.well-known/jwks.json"
            });
        }
    }
}
