
using GlobalAuth.Api.Repositories;

namespace GlobalAuth.Api.Services;

public sealed class ApplicationService
{
	private readonly ApplicationRepository _applicationRepository;
	public ApplicationService(ApplicationRepository applicationRepository)
	{
		_applicationRepository = applicationRepository;
	}
	public async Task DeactivateApplicationAsync(string applicationId,string updatedBy,CancellationToken cancellationToken = default)
	{
		if (string.IsNullOrWhiteSpace(applicationId))
			throw new ArgumentException("Application ID is required.", nameof(applicationId));
		if (string.IsNullOrWhiteSpace(updatedBy))
			throw new ArgumentException("Employee ID is required.", nameof(updatedBy));
		await _applicationRepository.DeactivateAsync(applicationId,updatedBy,cancellationToken);
	}

	public async Task ReactivateApplicationAsync(string applicationId,string updatedBy,CancellationToken cancellationToken = default)
	{
		if (string.IsNullOrWhiteSpace(applicationId))
			throw new ArgumentException("Application ID is required.", nameof(applicationId));
		if (string.IsNullOrWhiteSpace(updatedBy))
			throw new ArgumentException("Employee ID is required.", nameof(updatedBy));
		await _applicationRepository.ReactivateAsync(applicationId,updatedBy,cancellationToken);
	}
	public async Task<bool> UpdateConfigurationAsync(
	string applicationId,
	bool allowMultipleUserSessions,
	int maxActiveUserSessions,
	int idleTimeoutMinutes,
	string updatedBy,
	CancellationToken cancellationToken = default)
	{
		if (string.IsNullOrWhiteSpace(applicationId))
			throw new ArgumentException("Application ID is required.");

		if (string.IsNullOrWhiteSpace(updatedBy))
			throw new ArgumentException("UpdatedBy is required.");

		if (maxActiveUserSessions < 1)
			throw new ArgumentException(
				"Maximum active sessions must be at least 1.");

		if (!allowMultipleUserSessions && maxActiveUserSessions != 1)
			throw new ArgumentException(
				"Maximum active sessions must be 1 when multiple sessions are disabled.");

		if (idleTimeoutMinutes < 1)
			throw new ArgumentException(
				"Idle timeout must be at least 1 minute.");

		return await _applicationRepository.UpdateConfigurationAsync(
			applicationId,
			allowMultipleUserSessions,
			maxActiveUserSessions,
			idleTimeoutMinutes,
			updatedBy,
			cancellationToken);
	}
}
