
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

	public async Task DeactivateClientAsync(
		string clientId,
		CancellationToken cancellationToken = default)
	{
		if (string.IsNullOrWhiteSpace(clientId))
		{
			throw new ArgumentException(
				"Client ID is required.",
				nameof(clientId));
		}

		await _clientCredentialRepository.DeactivateAsync(
			clientId,
			cancellationToken);
	}

	public async Task ReactivateClientAsync(
		string clientId,
		CancellationToken cancellationToken = default)
	{
		if (string.IsNullOrWhiteSpace(clientId))
		{
			throw new ArgumentException(
				"Client ID is required.",
				nameof(clientId));
		}

		await _clientCredentialRepository.ReactivateAsync(
			clientId,
			cancellationToken);
	}
}
