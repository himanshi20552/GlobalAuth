using Microsoft.IdentityModel.Tokens;
namespace GlobalAuth.Api.Services
{
    public interface ISigningKeyProvider
    {
        SigningCredentials GetSigningCredentials();
    }
}
