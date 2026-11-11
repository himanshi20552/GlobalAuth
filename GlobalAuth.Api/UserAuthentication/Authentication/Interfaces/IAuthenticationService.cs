using ApplicationAuthentication.Authentication;

namespace ApplicationAuthentication.Authentication.Interfaces;

public interface IAuthenticationService
{
	Task<UserAuthenticationResult?> AuthenticateUserAsync (string userId, string password);
}
