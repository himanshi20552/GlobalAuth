namespace ApplicationAuthentication.Repositories.Interfaces;

public interface IUserApplicationRepository
{
	Task<bool> IsUserAssignedToApplicationAsync(string userId, string applicationId);
}
