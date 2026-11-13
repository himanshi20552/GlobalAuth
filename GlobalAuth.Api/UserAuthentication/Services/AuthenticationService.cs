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
			_passwordHashingService.VerifyPassword(user.PasswordHash, password);

		if (passwordVerificationResult == PasswordVerificationResult.Failed)
		{
			return null;
		}

		if (passwordVerificationResult == PasswordVerificationResult.SuccessRehashNeeded)
		{
			var newPasswordHash = _passwordHashingService.HashPassword(password);

			await _userRepository.UpdatePasswordHashAsync(
				user.UserId,
				newPasswordHash,cancellationToken);
		}

		return new UserAuthenticationResult
		{
			UserId = user.UserId,
			UserName = user.UserName
		};
	}
}