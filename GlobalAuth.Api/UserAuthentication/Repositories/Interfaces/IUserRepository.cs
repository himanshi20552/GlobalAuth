using ApplicationAuthentication.Entities;
namespace ApplicationAuthentication.Repositories.Interfaces
{
    public interface IUserRepository
    {
        Task<User?> GetByUserIdAsync(string userId);
		Task UpdatePasswordHashAsync(string userId, string newPasswordHash);
	}
}
