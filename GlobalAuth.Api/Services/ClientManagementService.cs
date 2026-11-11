
using GlobalAuth.Api.Repositories;

namespace GlobalAuth.Api.Services;

public sealed class ClientManagementService
{
	private readonly ClientCredentialRepository _clientCredentialRepository;
	public ClientManagementService(
		ClientCredentialRepository clientCredentialRepository)
	{
		_clientCredentialRepository = clientCredentialRepository;
	}
	public async Task DeactivateClientAsync(string clientId,string updatedBy,
		CancellationToken cancellationToken = default)
	{
		if (string.IsNullOrWhiteSpace(clientId))
			throw new ArgumentException("Client ID is required.",nameof(clientId));
		if (string.IsNullOrWhiteSpace(updatedBy))
			throw new ArgumentException("Employee ID is required.", nameof(updatedBy));
		await _clientCredentialRepository.DeactivateAsync(clientId,updatedBy,cancellationToken);
	}

	public async Task ReactivateClientAsync(string clientId,string updatedBy,CancellationToken cancellationToken = default)
	{
		if (string.IsNullOrWhiteSpace(clientId))
			throw new ArgumentException("Client ID is required.",nameof(clientId));
		if (string.IsNullOrWhiteSpace(updatedBy))
			throw new ArgumentException("Employee ID is required.", nameof(updatedBy));
		await _clientCredentialRepository.ReactivateAsync(clientId,updatedBy,cancellationToken);
	}
}
