namespace GlobalAuth.Api.Models;
public sealed class ClientRefreshTokenContext
{
	public string ClientID { get; set; } = string.Empty;
	public DateTime TokenExpiresAtUtc { get; set; }
	public DateTime? UsedAtUtc { get; set; }
	public DateTime? RevokedAtUtc { get; set; }
	public bool ClientIsActive { get; set; }
}
