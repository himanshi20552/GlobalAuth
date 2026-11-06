namespace GlobalAuth.Api.Models;

public enum SessionCreationResult
{
	Created=0,SessionLimitReached=1,ApplicationInactive=2, ClientInactive=3
}