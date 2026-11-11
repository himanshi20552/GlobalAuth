namespace ApplicationAuthentication.Contracts;

public sealed class UserAuthorizationResult
{
	public List<string> Roles { get; set; } = new();
	public List<string> Permissions { get; set; } = new();
}
