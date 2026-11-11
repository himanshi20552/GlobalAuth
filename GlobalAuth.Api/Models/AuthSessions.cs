namespace GlobalAuth.Api.Models;

public sealed class AuthSession
{
	public Guid SessionID { get; set; }
	public string SubjectID { get; set; } = string.Empty;
	public string? ApplicationID { get; set; }
	public DateTime CreatedAtUtc { get; set; }
	public DateTime LastActivityAtUtc { get; set; }
	public byte StatusID { get; set; }
	public DateTime? RevokedAtUtc { get; set; }
	public string? RevocationSource { get; set; }
}
