using GlobalAuth.Api.Repositories;
using GlobalAuth.Api.Models;

namespace GlobalAuth.Api.Services;

public sealed class SessionService
{
	private readonly AuthSessionRepository _authSessionRepository;

	public SessionService(AuthSessionRepository authSessionRepository)
	{
		_authSessionRepository = authSessionRepository;
	}


	public async Task<Guid> CreateUserSessionAsync(string subjectId,string applicationId,
		string expectedPasswordHash,CancellationToken cancellationToken = default)
	{
		if (string.IsNullOrWhiteSpace(subjectId))
			throw new ArgumentException("User ID is required.");

		if (string.IsNullOrWhiteSpace(applicationId))
			throw new ArgumentException("Application ID is required.");
		if (string.IsNullOrWhiteSpace(expectedPasswordHash))
			throw new ArgumentException("Verified password hash is required.");

		var now = DateTime.UtcNow;

		var session = new AuthSession
		{
			SessionID = Guid.NewGuid(),
			SubjectID = subjectId,
			ApplicationID = applicationId,
			CreatedAtUtc = now,
			LastActivityAtUtc = now,
			StatusID = 1
		};

		var result = await _authSessionRepository.CreateUserSessionAsync(
			session,expectedPasswordHash, cancellationToken);

		return result switch
		{
			SessionCreationResult.Created => session.SessionID,

			SessionCreationResult.SessionLimitReached =>
				throw new InvalidOperationException(
					"The maximum number of active sessions has been reached."),

			SessionCreationResult.ApplicationInactive =>
				throw new InvalidOperationException(
					"The application is inactive or not registered."),
			SessionCreationResult.CredentialsChanged =>
				throw new UnauthorizedAccessException("Credentials have changed. Please log in again."),

			_ => throw new InvalidOperationException(
				"Unexpected session creation result.")
		};
	}


	public async Task RevokeSessionAsync(
		Guid sessionId,
		string revocationSource,
		CancellationToken cancellationToken = default)
	{
		if (sessionId == Guid.Empty)
			throw new ArgumentException("Session ID is required.");

		if (string.IsNullOrWhiteSpace(revocationSource))
			throw new ArgumentException("Revocation source is required.");

		await _authSessionRepository.RevokeAsync(
			sessionId, revocationSource, cancellationToken);
	}

	public async Task<IReadOnlyList<AuthSession>> GetActiveSessionsAsync(
		string subjectId,
		string applicationId,
		CancellationToken cancellationToken = default)
	{
		if (string.IsNullOrWhiteSpace(subjectId))
			throw new ArgumentException("User ID is required.");

		if (string.IsNullOrWhiteSpace(applicationId))
			throw new ArgumentException("Application ID is required.");

		return await _authSessionRepository.GetActiveBySubjectAsync(
			subjectId, applicationId, cancellationToken);
	}

	public async Task<bool> RevokeOwnedSessionAsync(
		Guid sessionId,
		string subjectId,
		string applicationId,
		string revocationSource,
		CancellationToken cancellationToken = default)
	{
		if (sessionId == Guid.Empty)
			throw new ArgumentException("Session ID is required.");

		if (string.IsNullOrWhiteSpace(subjectId))
			throw new ArgumentException("User ID is required.");

		if (string.IsNullOrWhiteSpace(applicationId))
			throw new ArgumentException("Application ID is required.");

		if (string.IsNullOrWhiteSpace(revocationSource))
			throw new ArgumentException("Revocation source is required.");

		return await _authSessionRepository.RevokeOwnedAsync(
			sessionId,
			subjectId,
			applicationId,
			revocationSource,
			cancellationToken);
	}

	public async Task RevokeAllActiveSessionsAsync(
		string subjectId,
		string applicationId,
		string revocationSource,
		CancellationToken cancellationToken = default)
	{
		if (string.IsNullOrWhiteSpace(subjectId))
			throw new ArgumentException("User ID is required.");

		if (string.IsNullOrWhiteSpace(applicationId))
			throw new ArgumentException("Application ID is required.");

		if (string.IsNullOrWhiteSpace(revocationSource))
			throw new ArgumentException("Revocation source is required.");

		await _authSessionRepository.RevokeAllActiveAsync(
			subjectId,
			applicationId,
			revocationSource,
			cancellationToken);
	}

	public async Task<bool> IsSessionValidAsync(Guid sessionId,string subjectId,string applicationId,
		CancellationToken cancellationToken = default)
	{
		if (sessionId == Guid.Empty)
			throw new ArgumentException("Session ID is required.");
		if (string.IsNullOrWhiteSpace(subjectId))
			throw new ArgumentException("User ID is required.");
		if (string.IsNullOrWhiteSpace(applicationId))
			throw new ArgumentException("Application ID is required.");
		return await _authSessionRepository.IsSessionValidAsync(sessionId,subjectId,
			applicationId,
			cancellationToken);
	}

}
