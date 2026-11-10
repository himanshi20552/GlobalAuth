namespace GlobalAuth.Api.Configuration;

public class JwtOptions
{
	public string KeyId { get; set; } = "global-auth-dev-1";
	public string? SigningKeyPath { get; set; }
	public string Issuer { get; set; } = "GlobalAuth";
	public string Audience { get; set; } = "GlobalAuthApis";
	public int AccessTokenLifetimeMinutes { get; set; } = 15;
	public string PublicBaseUrl { get; set; } = string.Empty;
}