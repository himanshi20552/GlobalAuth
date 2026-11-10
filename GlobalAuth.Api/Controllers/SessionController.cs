using GlobalAuth.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace GlobalAuth.Api.Controllers
{
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
        public async Task<IActionResult> GetActiveSessions(CancellationToken cancellationToken)
        {
            var subjectId = User.FindFirst("sub")?.Value;
            var principalType = User.FindFirst("principal_type")?.Value;
            var applicationId = User.FindFirst("client_id")?.Value;
            var currentSessionId = User.FindFirst("sid")?.Value;
            if (string.IsNullOrWhiteSpace(subjectId) || string.IsNullOrWhiteSpace(principalType) ||
                string.IsNullOrWhiteSpace(applicationId) || !Guid.TryParse(currentSessionId, out var currentSessionGuid))
            {
                return Unauthorized(new
                {
                    message = "Required Information is missing."
                });

            }
            IReadOnlyList<Models.AuthSession> sessions;
            if (principalType == "USER")
            {
                sessions = await _sessionService.GetActiveSessionsAsync(subjectType: "USER",
                    subjectId: subjectId, applicationId: applicationId, cancellationToken: cancellationToken);
            }
            else if (principalType == "CLIENT")
            {
                if (subjectId != applicationId)
                {
                    return Unauthorized(new
                    {
                        message = "Invalid client identity"
                    });
                }
                sessions = await _sessionService.GetActiveSessionsAsync(subjectType: "CLIENT", subjectId: subjectId,
                    applicationId: null, cancellationToken: cancellationToken);

            }
            else {
                return Unauthorized(new
                {
                    message = "Invalid principal type"
                });
            }
            var response = sessions.Select(session => new
            {
                session.SessionID,
                session.SubjectType,
                session.DeviceID,
                session.IPAddress,
                session.UserAgent,
                session.CreatedAtUtc,
                session.LastActivityAtUtc,
                session.ExpiresAtUtc,
                IsCurrentSession = session.SessionID == currentSessionGuid
            });
            return Ok(response);
        }
        [HttpDelete("{sessionId:guid}")]
        public async Task<IActionResult> RevokeSession(Guid sessionId, CancellationToken cancellationToken)
        {
            var subjectId = User.FindFirst("sub")?.Value;
			var principalType = User.FindFirst("principal_type")?.Value;
			var applicationId = User.FindFirst("client_id")?.Value;

			if (string.IsNullOrWhiteSpace(subjectId) ||string.IsNullOrWhiteSpace(principalType) ||
		      string.IsNullOrWhiteSpace(applicationId))
			{
				return Unauthorized(new
				{
					message = "Required identity information is missing."
				});
			}
			string subjectType;
			string? scopedApplicationId;
			if (principalType == "USER")
			{
				subjectType = "USER";
				scopedApplicationId = applicationId;
			}
			else if (principalType == "CLIENT")
			{
				// For machine clients, sub and client_id must be same.
				if (subjectId != applicationId)
				{
					return Unauthorized(new
					{
						message = "Invalid client identity."
					});
				}

				subjectType = "CLIENT";
				scopedApplicationId = null;
			}
			else
			{
				return Unauthorized(new
				{
					message = "Invalid principal type."
				});
			}
            var revoked = await _sessionService.RevokeOwnedSessionAsync(sessionId, subjectType, subjectId, scopedApplicationId,
                "Revoked by session owner",cancellationToken);
			if (!revoked)
			{
				return NotFound(new
				{
					message = "Active session not found."
				});
			}
			return NoContent();

		}
	}
}
