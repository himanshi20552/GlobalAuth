namespace ApplicationAuthentication.Authentication;

public class UserAuthenticationResult
{
	public string UserId { get; set; } = string.Empty;
	public string UserName { get; set; } = string.Empty;
	public string PasswordHash { get; set; } = string.Empty;
}