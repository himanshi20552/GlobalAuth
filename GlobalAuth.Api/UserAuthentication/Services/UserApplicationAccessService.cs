using ApplicationAuthentication.Repositories.Interfaces;
using ApplicationAuthentication.Services.Interfaces;

namespace ApplicationAuthentication.Services;

public class UserApplicationAccessService : IUserApplicationAccessService
{
	private readonly IUserApplicationRepository _userApplicationRepository;
	public UserApplicationAccessService(IUserApplicationRepository userApplicationRepository)
	{
		_userApplicationRepository = userApplicationRepository;
	}
	public async Task<bool> IsUserAllowedAsync(string userId, string applicationId)
	{
		return await _userApplicationRepository.IsUserAssignedToApplicationAsync(userId, applicationId);
	}

}
