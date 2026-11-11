namespace ApplicationAuthentication.Services.Interfaces;

public interface IUserApplicationAccessService
{
	Task<bool> IsUserAllowedAsync(string userId, string applicationId);
}
