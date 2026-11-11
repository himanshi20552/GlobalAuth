using ApplicationAuthentication.Authentication;
using ApplicationAuthentication.Authentication.Interfaces;
using ApplicationAuthentication.Repositories.Interfaces;
using ApplicationAuthentication.Services.Interfaces;
using Microsoft.AspNetCore.Identity;

namespace ApplicationAuthentication.Services;

public class AuthenticationService : IAuthenticationService{
	private readonly IUserRepository _userRepository;
	private readonly IPasswordHashingService _passwordHashingService;

	public AuthenticationService( // constructor dependency injection 
		IUserRepository userRepository, IPasswordHashingService passwordHashingService)
	{
		_userRepository = userRepository;
		_passwordHashingService = passwordHashingService;
	}
	public async Task<UserAuthenticationResult?> AuthenticateUserAsync(string userId, string password)
	{
		var user = await _userRepository.GetByUserIdAsync(userId); // status validation
		if (user == null || !user.IsActive || user.IsBlocked)
		{
			return null;
		}
		var passwordVerificationResult = _passwordHashingService.VerifyPassword(user.PasswordHash, password); // password validation
		if (passwordVerificationResult == PasswordVerificationResult.Failed) { return null; }
		if (passwordVerificationResult == PasswordVerificationResult.SuccessRehashNeeded)
		{
			var newPasswordHash = _passwordHashingService.HashPassword(password);
			await _userRepository.UpdatePasswordHashAsync(user.UserId, newPasswordHash);
		}
		return new UserAuthenticationResult
		{
			UserId = user.UserId,
			UserName = user.UserName
		};
	}
}
