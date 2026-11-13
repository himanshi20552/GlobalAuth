
using GlobalAuth.Api.Repositories;

namespace GlobalAuth.Api.Services;

using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
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

	public async Task<string?> RotateClientSecretAsync(
		string clientId,
		string updatedBy,
		CancellationToken cancellationToken = default)
	{
		if (string.IsNullOrWhiteSpace(clientId))
			throw new ArgumentException("Client ID is required.", nameof(clientId));

		if (string.IsNullOrWhiteSpace(updatedBy))
			throw new ArgumentException("Employee ID is required.", nameof(updatedBy));

		// Generate 32 cryptographically random bytes (256 bits).
		var secretBytes = RandomNumberGenerator.GetBytes(32);

		// Convert to a URL-safe string.
		var newSecret = WebEncoders.Base64UrlEncode(secretBytes);

		// Store only the SHA-256 hash.
		var secretHash = SHA256.HashData(
			Encoding.UTF8.GetBytes(newSecret));

		var updated = await _clientCredentialRepository.RotateSecretAsync(
			clientId,
			secretHash,
			updatedBy,
			cancellationToken);

		if (!updated)
			return null;

		// Return plaintext only after successful database update.
		return newSecret;
	}

}
