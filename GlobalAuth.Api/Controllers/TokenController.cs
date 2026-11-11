
using GlobalAuth.Api.Contracts;
using GlobalAuth.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
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
	[EnableRateLimiting("TokenOperationsLimit")]
	[HttpPost("refresh")]
	public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request, CancellationToken cancellationToken)
	{
		if (string.IsNullOrWhiteSpace(request.RefreshToken))
		{
			return BadRequest(new
			{
				message = "Refresh token is required."
			});
		}

		var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

		try
		{
			var result = await _tokenRefreshService.RefreshAsync(
				request.RefreshToken,
				ipAddress: ipAddress,
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
	[AllowAnonymous]
	[EnableRateLimiting("TokenOperationsLimit")]
	[HttpPost("logout")]
	public async Task<IActionResult> Logout([FromBody] RefreshTokenRequest request, CancellationToken cancellationToken)
	{
		if (string.IsNullOrWhiteSpace(request.RefreshToken))
		{
			return BadRequest(new
			{
				message = "Refresh token required."
			});
		}
		await _tokenRefreshService.LogoutAsync(request.RefreshToken, cancellationToken);
		return NoContent();

	}
}
