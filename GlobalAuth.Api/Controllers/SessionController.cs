
using GlobalAuth.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace GlobalAuth.Api.Controllers;

[ApiController]
[Route("api/auth/sessions")]
[Authorize]
public sealed class SessionController : ControllerBase
{
	private readonly SessionService _sessionService;

	public SessionController(SessionService sessionService)
	{
		_sessionService = sessionService;
	}

	[HttpGet]
	public async Task<IActionResult> GetActiveSessions(
		CancellationToken cancellationToken)
	{
		var subjectId = User.FindFirst("sub")?.Value;
		var principalType = User.FindFirst("principal_type")?.Value;
		var applicationId = User.FindFirst("client_id")?.Value;
		var currentSessionId = User.FindFirst("sid")?.Value;

		if (principalType != "USER")
			return Forbid();

		if (string.IsNullOrWhiteSpace(subjectId) ||
			string.IsNullOrWhiteSpace(applicationId) ||
			!Guid.TryParse(currentSessionId, out var currentSessionGuid))
		{
			return Unauthorized(new
			{
				message = "Required user session information is missing."
			});
		}

		var sessions = await _sessionService.GetActiveSessionsAsync(
			subjectId,
			applicationId,
			cancellationToken);

		var response = sessions.Select(session => new
		{
			session.SessionID,
			session.CreatedAtUtc,
			session.LastActivityAtUtc,
			IsCurrentSession = session.SessionID == currentSessionGuid
		});

		return Ok(response);
	}

	[HttpDelete("{sessionId:guid}")]
	public async Task<IActionResult> RevokeSession(
		Guid sessionId,
		CancellationToken cancellationToken)
	{
		var subjectId = User.FindFirst("sub")?.Value;
		var principalType = User.FindFirst("principal_type")?.Value;
		var applicationId = User.FindFirst("client_id")?.Value;

		if (principalType != "USER")
			return Forbid();

		if (string.IsNullOrWhiteSpace(subjectId) ||
			string.IsNullOrWhiteSpace(applicationId))
		{
			return Unauthorized(new
			{
				message = "Required user identity information is missing."
			});
		}

		var revoked = await _sessionService.RevokeOwnedSessionAsync(
			sessionId,
			subjectId,
			applicationId,
			"SessionController.RevokeSession",
			cancellationToken);

		if (!revoked)
		{
			return NotFound(new
			{
				message = "Active session not found."
			});
		}

		return NoContent();
	}

	[HttpDelete]
	public async Task<IActionResult> RevokeAllSessions(
		CancellationToken cancellationToken)
	{
		var subjectId = User.FindFirst("sub")?.Value;
		var principalType = User.FindFirst("principal_type")?.Value;
		var applicationId = User.FindFirst("client_id")?.Value;

		if (principalType != "USER")
			return Forbid();

		if (string.IsNullOrWhiteSpace(subjectId) ||
			string.IsNullOrWhiteSpace(applicationId))
		{
			return Unauthorized(new
			{
				message = "Required user identity information is missing."
			});
		}

		await _sessionService.RevokeAllActiveSessionsAsync(subjectId,applicationId,
			"SessionController.RevokeAllSessions",
			cancellationToken);

		return NoContent();
	}
}
