namespace GlobalAuth.Api.Contracts
{
    public sealed class TokenIssuanceRequest
    {
		public string PrincipalType { get; set; } = string.Empty;
		public string SubjectId { get; set; } = string.Empty;
		public string? ApplicationId { get; set; }
		public List<string> Roles { get; set; } = [];
		public List<string> Permissions { get; set; } = [];
		// Audit metadata
		public string? IpAddress { get; set; }
		// Internal credential verification. Never sent to clients.
		public string? VerifiedPasswordHash { get; set; }

	}
}
