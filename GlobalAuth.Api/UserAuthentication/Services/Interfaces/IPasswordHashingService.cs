using Microsoft.AspNetCore.Identity;

namespace ApplicationAuthentication.Services.Interfaces;

public interface IPasswordHashingService
{
	string HashPassword(string password);

	PasswordVerificationResult VerifyPassword(string passwordHash,string providedPassword);
}