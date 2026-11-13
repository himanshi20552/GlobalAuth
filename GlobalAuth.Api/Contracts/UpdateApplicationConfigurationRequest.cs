namespace GlobalAuth.Api.Contracts;

public sealed class UpdateApplicationConfigurationRequest
{
	public bool AllowMultipleUserSessions { get; set; }

	public int MaxActiveUserSessions { get; set; }

	public int IdleTimeoutMinutes { get; set; }
}