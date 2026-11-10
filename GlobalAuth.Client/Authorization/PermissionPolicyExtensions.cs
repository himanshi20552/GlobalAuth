
using Microsoft.AspNetCore.Authorization;

namespace GlobalAuth.Client.Authorization;

public static class PermissionPolicyExtensions
{

	public static AuthorizationPolicyBuilder RequirePermission(
		this AuthorizationPolicyBuilder policy,
		string permission)
	{
		ArgumentNullException.ThrowIfNull(policy);
		ArgumentException.ThrowIfNullOrWhiteSpace(permission);

		policy.RequireAuthenticatedUser();

		policy.AddRequirements(new PermissionRequirement(permission));

		return policy;
	}
}

