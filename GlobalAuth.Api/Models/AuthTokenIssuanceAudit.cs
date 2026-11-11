
namespace GlobalAuth.Api.Models;

public sealed class AuthTokenIssuanceAudit
{
	public long AuditID { get; set; }
	public string Jti { get; set; } = string.Empty;
	public string PrincipalType { get; set; } = string.Empty;
	public string SubjectID { get; set; } = string.Empty;
	public Guid? SessionID { get; set; }
	public string IssuanceType { get; set; } = string.Empty;
	public DateTime IssuedAtUtc { get; set; }
	public DateTime ExpiresAtUtc { get; set; }
	public string? IPAddress { get; set; }
}
