
namespace EmployeePortalDemo.Models.Responses;

public class LoginResponse
{
	public string AccessToken { get; set; } = string.Empty;

	public string RefreshToken { get; set; } = string.Empty;

	public DateTime ExpiresAtUtc { get; set; }
}
