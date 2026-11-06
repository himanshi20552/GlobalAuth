namespace GlobalAuth.Api.Models;

public sealed class RefreshTokenContext
{
	public Guid SessionID { get; set; }
	public string SubjectType { get; set; } = string.Empty;
	public string SubjectID { get; set; } = string.Empty;
	public string? ApplicationID { get; set; }
	public DateTime SessionExpiresAtUtc { get; set; }
	public DateTime TokenExpiresAtUtc { get; set; }
	public DateTime? UsedAtUtc { get; set; }
	public DateTime? RevokedAtUtc { get; set; }
	public DateTime? SessionRevokedAtUtc { get; set; }
}