namespace ApplicationAuthentication.Services.Interfaces;

public interface IApplicationValidationService
{
	Task<bool> ValidateApplicationAsync(string applicationId,string hashKey,
		CancellationToken cancellationToken = default);
}