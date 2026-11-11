using ApplicationAuthentication.Entities;
using ApplicationAuthentication.Services.Interfaces;
using Microsoft.AspNetCore.Identity;

namespace ApplicationAuthentication.Services;

public class PasswordHashingService : IPasswordHashingService
{
	private readonly PasswordHasher<User> _passwordHasher;

	public PasswordHashingService()
	{
		_passwordHasher = new PasswordHasher<User>();
	}

	public string HashPassword(string password)
	{
		return _passwordHasher.HashPassword(new User(), password);
	}

	public PasswordVerificationResult VerifyPassword(
		string passwordHash,
		string providedPassword)
	{
		var result = _passwordHasher.VerifyHashedPassword(
			new User(),
			passwordHash,
			providedPassword);

		return result;
	}
}