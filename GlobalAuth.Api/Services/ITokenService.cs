using GlobalAuth.Api.Contracts;
namespace GlobalAuth.Api.Services
{
    public interface ITokenService
    {
		TokenResult GenerateAccessToken(TokenGenerationRequest request);
	}
}
