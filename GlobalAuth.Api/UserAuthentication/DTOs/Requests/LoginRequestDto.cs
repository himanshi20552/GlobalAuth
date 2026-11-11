namespace ApplicationAuthentication.DTOs.Requests;

public class LoginRequestDto
{

	public string ApplicationId { get; set; } = string.Empty;
	public string HashKey { get; set; } = string.Empty;
	public string UserId { get; set; } = string.Empty;
	public string Password { get; set; } = string.Empty;
	
}
