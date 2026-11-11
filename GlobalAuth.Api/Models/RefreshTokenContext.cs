
namespace GlobalAuth.Api.Models;

public sealed class RefreshTokenContext
{
	public Guid SessionID { get; set; }
	public string SubjectID { get; set; } = string.Empty;
	public string? ApplicationID { get; set; }

	public byte SessionStatusID { get; set; }
	public DateTime LastActivityAtUtc { get; set; }
	public int IdleTimeoutMinutes { get; set; }
	public bool ApplicationIsActive { get; set; }

	public DateTime TokenExpiresAtUtc { get; set; }
	public DateTime? UsedAtUtc { get; set; }
	public DateTime? RevokedAtUtc { get; set; }
	public DateTime? SessionRevokedAtUtc { get; set; }
}
