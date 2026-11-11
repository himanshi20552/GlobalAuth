namespace ApplicationAuthentication.DTOs.Responses;
public class LoginResponseDto
{
	public string UserId { get; set; } = string.Empty;
	public string UserName { get; set; } = string.Empty;
	public IEnumerable<string> Groups { get; set; } = Enumerable.Empty<string>();
	public IEnumerable<string> Permissions { get; set; } = Enumerable.Empty<string>();
}
