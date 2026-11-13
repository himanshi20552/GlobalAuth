using ApplicationAuthentication.Authentication;
using ApplicationAuthentication.Authentication.Interfaces;
using ApplicationAuthentication.Repositories.Interfaces;
using ApplicationAuthentication.Services.Interfaces;
using Microsoft.AspNetCore.Identity;

namespace ApplicationAuthentication.Services;

public class AuthenticationService : IAuthenticationService
{
	private readonly IUserRepository _userRepository;
	private readonly IPasswordHashingService _passwordHashingService;

	public AuthenticationService(
		IUserRepository userRepository,
		IPasswordHashingService passwordHashingService)
	{
		_userRepository = userRepository;
		_passwordHashingService = passwordHashingService;
	}

	public async Task<UserAuthenticationResult?> AuthenticateUserAsync(
	string userId,
	string password,
	CancellationToken cancellationToken = default)
	{
		var user = await _userRepository
			.GetByUserIdAsync(userId, cancellationToken);

		if (user == null || !user.IsActive || user.IsBlocked)
		{
			return null;
		}

		var passwordVerificationResult =
			_passwordHashingService.VerifyPassword(
				user.PasswordHash,
				password);

		if (passwordVerificationResult ==
			PasswordVerificationResult.Failed)
		{
			return null;
		}

		// Upgrade the password hash if required.
		if (passwordVerificationResult ==
			PasswordVerificationResult.SuccessRehashNeeded)
		{
			var newPasswordHash =
				_passwordHashingService.HashPassword(password);

			var updated = await _userRepository.UpdatePasswordHashAsync(
				user.UserId,
				user.PasswordHash,
				newPasswordHash,
				cancellationToken);

			if (!updated)
			{
				return null;
			}

			user.PasswordHash = newPasswordHash;
		}

		return new UserAuthenticationResult
		{
			UserId = user.UserId,
			UserName = user.UserName,
			PasswordHash = user.PasswordHash
		};
	}
}