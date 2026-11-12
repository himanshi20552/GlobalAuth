using ApplicationAuthentication.Entities;

namespace ApplicationAuthentication.Repositories.Interfaces
{
	public interface IUserRepository
	{
		Task<User?> GetByUserIdAsync(string userId,CancellationToken cancellationToken = default);

		Task UpdatePasswordHashAsync(string userId,string newPasswordHash,
			CancellationToken cancellationToken = default);
		Task<bool> ChangePasswordAndRevokeSessionsAsync(string userId,string applicationId,Guid currentSessionId,string currentPasswordHash,
	string newPasswordHash,string revocationSource,CancellationToken cancellationToken = default);
	}
}