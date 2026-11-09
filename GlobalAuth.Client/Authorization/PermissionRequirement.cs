using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Authorization;

namespace GlobalAuth.Client.Authorization
{
    public sealed class PermissionRequirement:IAuthorizationRequirement
    {
        public string Permission { get; }
        public PermissionRequirement(string permission)
		{
			ArgumentException.ThrowIfNullOrWhiteSpace(permission);
			Permission = permission;
		}

	}
}
