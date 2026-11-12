using ApplicationAuthentication.Repositories.Interfaces;
using ApplicationAuthentication.Services.Interfaces;

namespace ApplicationAuthentication.Services;

public class ApplicationValidationService : IApplicationValidationService
{
	private readonly IApplicationRepository _applicationRepository;

	public ApplicationValidationService(
		IApplicationRepository applicationRepository)
	{
		_applicationRepository = applicationRepository;
	}

	public async Task<bool> ValidateApplicationAsync(
		string applicationId,
		string hashKey,
		CancellationToken cancellationToken = default)
	{
		if (string.IsNullOrWhiteSpace(applicationId) ||
			string.IsNullOrWhiteSpace(hashKey))
		{
			return false;
		}

		var application = await _applicationRepository
			.GetByApplicationIdAsync(applicationId, cancellationToken);

		if (application == null || !application.IsActive)
		{
			return false;
		}

		return string.Equals(
			application.HashKey,
			hashKey,
			StringComparison.Ordinal);
	}
}