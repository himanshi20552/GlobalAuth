namespace GlobalAuth.Api.Contracts
{
    public class TokenResult
    {
		public string AccessToken { get; set; } = string.Empty;
		public string Jti { get; set; } = string.Empty;
		public DateTime ExpiresAtUtc { get; set; }

	}
}
