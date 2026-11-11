
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
}
