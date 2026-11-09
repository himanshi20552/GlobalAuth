
using GlobalAuth.Api.Contracts;
using GlobalAuth.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace GlobalAuth.Api.Controllers;

[ApiController]
[Route("api/auth")]
public sealed class TokenController : ControllerBase
{
	private readonly TokenRefreshService _tokenRefreshService;

	public TokenController(TokenRefreshService tokenRefreshService)
	{
		_tokenRefreshService = tokenRefreshService;
	}

	[AllowAnonymous]
	[HttpPost("refresh")]
	public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request,CancellationToken cancellationToken)
	{
		if (string.IsNullOrWhiteSpace(request.RefreshToken))
		{
			return BadRequest(new
			{
				message = "Refresh token is required."
			});
		}

		var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
		var userAgent = Request.Headers.UserAgent.ToString();

		try
		{
			var result = await _tokenRefreshService.RefreshAsync(
				request.RefreshToken,
				ipAddress: ipAddress,
				userAgent: userAgent,
				cancellationToken: cancellationToken);

			return Ok(result);
		}
		catch (UnauthorizedAccessException)
		{
			return Unauthorized(new
			{
				message = "Invalid or expired refresh token."
			});
		}
	}
}
