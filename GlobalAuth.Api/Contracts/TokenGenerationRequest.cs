namespace GlobalAuth.Api.Contracts
{
    public class TokenGenerationRequest
    {
		public string PrincipalType { get; set; } = string.Empty;
		public string SubjectId { get; set; } = string.Empty;
		public string? ApplicationId { get; set; }
		public List<string> Roles { get; set; } = [];
		public List<string> Permissions { get; set; } = [];
		public Guid SessionId { get; set; }
		public DateTime SessionExpiresAtUtc { get; set; }

	}
}
