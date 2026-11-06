namespace GlobalAuth.Api.Contracts
{
    public class RefreshTokenRequest
    {
		public string RefreshToken { get; set; } = string.Empty;

	}
	public sealed class RefreshTokenResponse
	{
		public string AccessToken { get; set; } = string.Empty;

		public string RefreshToken { get; set; } = string.Empty;

		public DateTime ExpiresAtUtc { get; set; }
	}
}
