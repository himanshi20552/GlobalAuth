namespace EmployeePortalDemo.Models.Responses;

public class LoginResponse
{
	public string UserId { get; set; } = string.Empty;
	public string UserName { get; set; } = string.Empty;
	public List<string> Groups { get; set; } = new();
	public List<string> Permissions { get; set; } = new();
}
