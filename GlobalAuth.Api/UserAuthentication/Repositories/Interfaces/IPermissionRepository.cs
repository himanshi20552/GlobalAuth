using ApplicationAuthentication.Entities;
namespace ApplicationAuthentication.Repositories.Interfaces;

public interface IPermissionRepository
{
	Task<IEnumerable<Permission>> GetPermissionsByUserIdAsync(string userId, string applicationId);
}
