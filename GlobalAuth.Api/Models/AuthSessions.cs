namespace GlobalAuth.Api.Models;

public class AuthSession
{
	public Guid SessionID { get; set; }
	public string SubjectType { get; set; } = string.Empty;
	public string SubjectID { get; set; } = string.Empty;
	public string? ApplicationID { get; set; }
	public string? DeviceID { get; set; }
	public string? IPAddress { get; set; }
	public string? UserAgent { get; set; }
	public DateTime CreatedAtUtc { get; set; }
	public DateTime LastActivityAtUtc { get; set; }
	public DateTime ExpiresAtUtc { get; set; }
	public DateTime? RevokedAtUtc { get; set; }
	public string? RevocationReason { get; set; }
}