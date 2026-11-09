
using GlobalAuth.Api.Repositories;

namespace GlobalAuth.Api.Services;

public sealed class ApplicationService
{
	private readonly ApplicationRepository _applicationRepository;
	public ApplicationService(ApplicationRepository applicationRepository)
	{
		_applicationRepository = applicationRepository;
	}
	public async Task DeactivateApplicationAsync(string applicationId,CancellationToken cancellationToken = default)
	{
		if (string.IsNullOrWhiteSpace(applicationId))
			throw new ArgumentException("Application ID is required.", nameof(applicationId));
		await _applicationRepository.DeactivateAsync(applicationId,cancellationToken);
	}

	public async Task ReactivateApplicationAsync(string applicationId,CancellationToken cancellationToken = default)
	{
		if (string.IsNullOrWhiteSpace(applicationId))
			throw new ArgumentException("Application ID is required.", nameof(applicationId));
		await _applicationRepository.ReactivateAsync(applicationId,cancellationToken);
	}
}
