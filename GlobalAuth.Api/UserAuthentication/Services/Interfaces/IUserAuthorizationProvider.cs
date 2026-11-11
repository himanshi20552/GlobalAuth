using ApplicationAuthentication.Contracts;

namespace ApplicationAuthentication.Services.Interfaces;

public interface IUserAuthorizationProvider
{
	Task<UserAuthorizationResult?> GetCurrentAuthorizationAsync(
		string userId, string applicationId,
		CancellationToken cancellationToken = default
		);
}
