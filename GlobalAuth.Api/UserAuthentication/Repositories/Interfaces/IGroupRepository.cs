using ApplicationAuthentication.Entities;
namespace ApplicationAuthentication.Repositories.Interfaces
{
    public interface IGroupRepository
    {
        Task<IEnumerable<Group>> GetGroupsByUserIdAsync(string userId, string applicationId);

    }
}
