using System.Security.Cryptography;
using System.Text;
using GlobalAuth.Api.Repositories;
using GlobalAuth.Api.Contracts;
using GlobalAuth.Api.Constants;

namespace GlobalAuth.Api.Services
{
    public sealed class ClientAuthenticationService
    {
        private readonly ClientCredentialRepository _repository;
		private readonly ClientPermissionRepository _permissionRepository;
		private readonly ITokenIssuanceService _tokenIssuanceService;
        public ClientAuthenticationService(ClientCredentialRepository repository, ClientPermissionRepository permissionRepository,
			ITokenIssuanceService tokenIssuanceService)
		{
			_repository = repository;
			_permissionRepository = permissionRepository;
			_tokenIssuanceService = tokenIssuanceService;
		}
		public async Task<RefreshTokenResponse?> AuthenticateAndIssueTokensAsync(string clientId, string clientSecret, 
			string? deviceId=null,string? IpAddress=null,string? userAgent=null,
			CancellationToken cancellationToken = default)
		{ 
			if(string.IsNullOrWhiteSpace(clientId)|| string.IsNullOrWhiteSpace(clientSecret))
			{
				return null;
			}
			//assuming we have generated at least 32 bytes of random data for the client secret and stored its hash in the database
			var storedHash = await _repository.GetActiveClientSecretHashAsync(clientId, cancellationToken);
			if(storedHash== null || storedHash.Length!=32)
			{
				return null;
			}
			var incomingHash=SHA256.HashData(Encoding.UTF8.GetBytes(clientSecret));
			var IsAuthenticated= CryptographicOperations.FixedTimeEquals(storedHash, incomingHash);
			if (!IsAuthenticated)
			{
				return null;
			}
			var permissions= await _permissionRepository.GetActivePermissionsByClientAsync(clientId, cancellationToken);

			var issuanceRequest = new TokenIssuanceRequest
			{
				PrincipalType = GlobalAuthPrincipalTypes.Client,
				SubjectId = clientId,
				ApplicationId = null,
				Roles = [],
				Permissions = permissions.ToList(),
				DeviceId = deviceId,
				IpAddress = IpAddress,
				UserAgent = userAgent
			};
			return await _tokenIssuanceService.IssueAsync(issuanceRequest, cancellationToken);
		}
	}
}
