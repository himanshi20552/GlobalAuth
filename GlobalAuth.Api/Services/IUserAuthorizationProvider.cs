using GlobalAuth.Api.Contracts;
namespace GlobalAuth.Api.Services;

public interface IUserAuthorizationProvider
{
	Task<UserAuthorizationResult?> GetCurrentAuthorizationAsync(
		string userId,
		string applicationId,
		CancellationToken cancellationToken = default);
}