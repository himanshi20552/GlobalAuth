using System.Security.Cryptography;
using System.Text;
using GlobalAuth.Api.Repositories;
namespace GlobalAuth.Api.Services
{
    public sealed class ClientAuthenticationService
    {
        private readonly ClientCredentialRepository _repository;
		private readonly ClientPermissionRepository _permissionRepository;
        public ClientAuthenticationService(ClientCredentialRepository repository, ClientPermissionRepository permissionRepository)
		{
			_repository = repository;
			_permissionRepository = permissionRepository;
		}
		public async Task<IReadOnlyList<string>?> AuthenticateAndGetPermissionsAsync(string clientId, string clientSecret, CancellationToken cancellationToken = default)
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
			return await _permissionRepository.GetActivePermissionsByClientAsync(clientId, cancellationToken);
		}
	}
}
