using Microsoft.AspNetCore.Authorization;

namespace GlobalAuth.Client.Authorization
{
    public sealed class PermissionAuthorizationHandler: AuthorizationHandler<PermissionRequirement>
	{
		protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement) { 
		bool hasPermission=context.User.HasClaim("permission", requirement.Permission);
			if(hasPermission)
			{
				context.Succeed(requirement);
			}
			return Task.CompletedTask;
		}

	}
}
