using GlobalAuth.Api.Contracts;
namespace GlobalAuth.Api.Services;
public interface ITokenIssuanceService
{
	Task<RefreshTokenResponse> IssueAsync(TokenIssuanceRequest request,
		CancellationToken cancellationToken = default);
}
