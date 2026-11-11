using ApplicationAuthentication.Entities;

namespace ApplicationAuthentication.Repositories.Interfaces;

public interface IApplicationRepository
{
	Task<Application?> GetByApplicationIdAsync(string applicationId);
}
