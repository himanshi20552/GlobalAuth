
using ApplicationAuthentication.Repositories.Interfaces;
using ApplicationAuthentication.Services.Interfaces;
using Microsoft.AspNetCore.Identity;

namespace ApplicationAuthentication.Services;

public sealed class PasswordChangeService : IPasswordChangeService
{
	private readonly IUserRepository _userRepository;
	private readonly IPasswordHashingService _passwordHashingService;

	public PasswordChangeService(
		IUserRepository userRepository,
		IPasswordHashingService passwordHashingService)
	{
		_userRepository = userRepository;
		_passwordHashingService = passwordHashingService;
	}

	public async Task<PasswordChangeResult> ChangePasswordAsync(
		string userId,
		string applicationId,
		Guid currentSessionId,
		string currentPassword,
		string newPassword,
		CancellationToken cancellationToken = default)
	{
		if (string.IsNullOrWhiteSpace(userId))
			throw new ArgumentException("User ID is required.");

		if (string.IsNullOrWhiteSpace(applicationId))
			throw new ArgumentException("Application ID is required.");

		if (currentSessionId == Guid.Empty)
			throw new ArgumentException("Current session ID is required.");

		if (string.IsNullOrWhiteSpace(currentPassword) ||
			string.IsNullOrWhiteSpace(newPassword))
			throw new ArgumentException("Passwords are required.");

		// 1. Retrieve the user.
		var user = await _userRepository.GetByUserIdAsync(
			userId,
			cancellationToken);

		if (user == null || !user.IsActive || user.IsBlocked)
			return PasswordChangeResult.UserUnavailable;

		// 2. Verify the current password.
		var verificationResult =
			_passwordHashingService.VerifyPassword(
				user.PasswordHash,
				currentPassword);

		if (verificationResult == PasswordVerificationResult.Failed)
			return PasswordChangeResult.InvalidCurrentPassword;

		// 3. Prevent changing to the same password.
		var newPasswordVerification =
			_passwordHashingService.VerifyPassword(
				user.PasswordHash,
				newPassword);

		if (newPasswordVerification != PasswordVerificationResult.Failed)
			return PasswordChangeResult.SameAsCurrentPassword;

		// 4. Generate the new password hash.
		var newPasswordHash =
			_passwordHashingService.HashPassword(newPassword);

		// 5. Update password and revoke sessions transactionally.
		var changed =
			await _userRepository.ChangePasswordAndRevokeSessionsAsync(
				userId,
				applicationId,
				currentSessionId,
				user.PasswordHash,
				newPasswordHash,
				"PasswordChangeService.ChangePasswordAsync",
				cancellationToken);

		return changed
			? PasswordChangeResult.Success
			: PasswordChangeResult.StateChanged;
	}
}
