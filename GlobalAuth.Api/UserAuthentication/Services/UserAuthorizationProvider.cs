using ApplicationAuthentication.Contracts;
using ApplicationAuthentication.Repositories.Interfaces;
using ApplicationAuthentication.Services.Interfaces;

namespace ApplicationAuthentication.Services;

public class UserAuthorizationProvider : IUserAuthorizationProvider
{
	private readonly IGroupRepository _groupRepository;
	private readonly IPermissionRepository _permissionRepository;
	private readonly IUserRepository _userRepository;
	private readonly IUserApplicationAccessService _userApplicationAccessService;


	public UserAuthorizationProvider(IGroupRepository groupRepository, IPermissionRepository permissionRepository,
		IUserRepository userRepository, IUserApplicationAccessService userApplicationAccessService)
	{

		_groupRepository = groupRepository;
		_permissionRepository = permissionRepository;
		_userRepository = userRepository;
		_userApplicationAccessService = userApplicationAccessService;
	}
	public async Task<UserAuthorizationResult?> GetCurrentAuthorizationAsync(string userId, string applicationId, 
		CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		var user = await _userRepository.GetByUserIdAsync(userId);
		if (user is null || !user.IsActive || user.IsBlocked)
		{
			return null;
		}
		var isAssigned = await _userApplicationAccessService 
			.IsUserAllowedAsync(userId, applicationId);
		if (!isAssigned)
		{
			return null;
		}
		var groups = await _groupRepository.GetGroupsByUserIdAsync(userId, applicationId);
		cancellationToken.ThrowIfCancellationRequested();
		var permissions = await _permissionRepository.GetPermissionsByUserIdAsync(userId, applicationId);
		return new UserAuthorizationResult
		{
			Roles = groups.Select(g => g.GroupName).ToList(),
			Permissions = permissions.Select(p => p.PermissionCode).ToList(),
		};
	}

}
