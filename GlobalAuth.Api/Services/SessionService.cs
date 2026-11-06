using GlobalAuth.Api.Configuration;
using GlobalAuth.Api.Contracts;
using GlobalAuth.Api.Repositories;
using Microsoft.Extensions.Options;
using GlobalAuth.Api.Models;

namespace GlobalAuth.Api.Services
{
    public sealed class SessionService
    {
        private readonly AuthSessionRepository _authSessionRepository;
        public SessionService(AuthSessionRepository authSessionRepository)
		{
			_authSessionRepository = authSessionRepository;
		}
		public async Task<Guid> CreateUserSessionAsync(SessionCreationRequest request, CancellationToken cancellationToken = default)
		{ 
			if(string.IsNullOrWhiteSpace(request.SubjectId))
			{
				throw new ArgumentException("User ID is required.");
			}
			if (string.IsNullOrWhiteSpace(request.ApplicationId))
			{
				throw new ArgumentException("Application ID is required.");
			}
			if (request.ExpiresAtUtc <= DateTime.UtcNow)
			{
				throw new ArgumentException("Expiration time must be in the future.");
			}
			var session=new AuthSession
			{
				SessionID = Guid.NewGuid(),
				SubjectType = "USER",
				SubjectID = request.SubjectId,
				ApplicationID = request.ApplicationId,
				DeviceID = request.DeviceId,
				IPAddress = request.IpAddress,
				UserAgent = request.UserAgent,
				CreatedAtUtc = DateTime.UtcNow,
				LastActivityAtUtc = DateTime.UtcNow,
				ExpiresAtUtc = request.ExpiresAtUtc
			};
			var result=await _authSessionRepository.CreateUserSessionAsync(session, cancellationToken);
			if(result== SessionCreationResult.SessionLimitReached)
			{
				throw new InvalidOperationException("Maximum active sessions reached.");
			}
			switch (result)
			{
				case SessionCreationResult.Created:
					return session.SessionID;

				case SessionCreationResult.SessionLimitReached:
					throw new InvalidOperationException(
						"The maximum number of active sessions has been reached.");

				case SessionCreationResult.ApplicationInactive:
					throw new InvalidOperationException(
						"The application is inactive or not registered.");

				default:
					throw new InvalidOperationException(
						"Unexpected session creation result.");
			}

		}
		public async Task<Guid> CreateClientSessionAsync(SessionCreationRequest request, CancellationToken cancellationToken = default)
		{
			if (string.IsNullOrWhiteSpace(request.SubjectId))
			{
				throw new ArgumentException("Client ID is required.");
			}
			if (!string.IsNullOrWhiteSpace(request.ApplicationId))
			{
				throw new ArgumentException("Application ID is not required for client sessions.");
			}
			var now = DateTime.UtcNow;
			if (request.ExpiresAtUtc <= now)
			{
				throw new ArgumentException("Expiration time must be in the future.");
			}
			var session = new AuthSession
			{
				SessionID = Guid.NewGuid(),
				SubjectType = "CLIENT",
				SubjectID = request.SubjectId,
				ApplicationID = null,
				DeviceID = request.DeviceId,
				IPAddress = request.IpAddress,
				UserAgent = request.UserAgent,
				CreatedAtUtc = now,
				LastActivityAtUtc = now,
				ExpiresAtUtc = request.ExpiresAtUtc
			};
			var result = await _authSessionRepository.CreateClientSessionAsync(session, cancellationToken);
			
			switch (result)
			{
				case SessionCreationResult.Created:
					return session.SessionID;
				case SessionCreationResult.ClientInactive:
					throw new InvalidOperationException(
						"The client is inactive or not registered.");
				default:
					throw new InvalidOperationException(
						"Unexpected session creation result.");
			}
		}
		public async Task RevokeSessionAsync(Guid sessionId,string reason,CancellationToken cancellationToken = default)
		{
			await _authSessionRepository.RevokeAsync(sessionId,reason,cancellationToken);
		}
	}
}
