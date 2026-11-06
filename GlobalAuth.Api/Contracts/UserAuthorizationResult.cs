namespace GlobalAuth.Api.Contracts;

public sealed class UserAuthorizationResult
{
	public List<string> Roles { get; set; } = [];
	public List<string> Permissions { get; set; } = [];
}