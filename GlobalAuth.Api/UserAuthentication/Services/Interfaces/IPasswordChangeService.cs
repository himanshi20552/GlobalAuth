
namespace ApplicationAuthentication.Services.Interfaces;

public enum PasswordChangeResult
{
Success,
	UserUnavailable,
	InvalidCurrentPassword,
	SameAsCurrentPassword,
	StateChanged
}

public interface IPasswordChangeService
{
	Task<PasswordChangeResult> ChangePasswordAsync(
		string userId,
		string applicationId,
		Guid currentSessionId,
		string currentPassword,
		string newPassword,
		CancellationToken cancellationToken = default);
}
