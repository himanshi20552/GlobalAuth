using GlobalAuth.Api.Contracts;
using GlobalAuth.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
namespace GlobalAuth.Api.Controllers
{
	[ApiController]
	[EnableRateLimiting("ClientTokenLimit")]
	[Route("api/auth/client")]
	public sealed class ClientAuthenticationController : ControllerBase
	{
		private readonly ClientAuthenticationService _clientAuthenticationService;
		public ClientAuthenticationController(ClientAuthenticationService clientAuthenticationService)
		{
			_clientAuthenticationService = clientAuthenticationService;
		}
		[AllowAnonymous]
		[HttpPost("token")]
		public async Task<IActionResult> GenerateToken([FromBody] ClientTokenRequest request, CancellationToken cancellationToken)
		{
			var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
			try
			{
				var result = await _clientAuthenticationService
					.AuthenticateAndIssueTokensAsync(
						request.ClientId,
						request.ClientSecret,
						IpAddress: ipAddress,
						cancellationToken: cancellationToken);

				if (result is null)
				{
					return Unauthorized(new
					{
						message = "Invalid Client Credentials"
					});
				}

				return Ok(result);
			}
			catch (UnauthorizedAccessException)
			{
				return Unauthorized(new
				{
					message = "Invalid Client Credentials"
				});
			}

		}
	}
}
