namespace ApplicationAuthentication.Services.Interfaces;

public interface IApplicationValidationService
{
	Task<bool> ValidateApplicationAsync(string applicationId, string hashaKey);

}
