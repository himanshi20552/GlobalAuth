namespace GlobalAuth.Client.Configuration;

public class GlobalAuthOptions
{
	public string Issuer { get; set; } = string.Empty;
	public string Audience { get; set; } = string.Empty;
	public string Authority { get; set; } = string.Empty;
	public string SessionValidationEndpoint { get; set; } = "/api/auth/sessions/validate";
}