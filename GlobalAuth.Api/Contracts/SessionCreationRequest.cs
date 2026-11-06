namespace GlobalAuth.Api.Contracts;

public sealed class SessionCreationRequest
{
	public string SubjectId { get; set; } = string.Empty;
	public string? ApplicationId { get; set; }
	public string? DeviceId { get; set; }
	public string? IpAddress { get; set; }
	public string? UserAgent { get; set; }
	public DateTime ExpiresAtUtc { get; set; }
}