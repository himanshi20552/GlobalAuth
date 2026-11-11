
using System.Data;
using Dapper;
using GlobalAuth.Api.Data;

namespace GlobalAuth.Api.Repositories;

public sealed class ClientRefreshTokenRepository
{
	private readonly SqlConnectionFactory _connFactory;

	public ClientRefreshTokenRepository(SqlConnectionFactory connFactory)
	{
		_connFactory = connFactory;
	}

	public async Task<bool> CreateAsync(
		Guid clientRefreshTokenId,
		string clientId,
		Guid familyId,
		byte[] tokenHash,
		DateTime expiresAtUtc,
		CancellationToken cancellationToken = default)
	{
		await using var conn = _connFactory.CreateConnection();
		await conn.OpenAsync(cancellationToken);

		var command = new CommandDefinition(
			commandText: "auth.CreateClientRefreshToken",
			parameters: new
			{
				ClientRefreshTokenID = clientRefreshTokenId,
				ClientID = clientId,
				FamilyID = familyId,
				TokenHash = tokenHash,
				ExpiresAtUtc = expiresAtUtc
			},
			commandType: CommandType.StoredProcedure,
			cancellationToken: cancellationToken);

		var resultCode = await conn.ExecuteScalarAsync<int>(command);

		return resultCode == 0;
	}

	public async Task<int> RotateAsync(byte[] presentedTokenHash,Guid newClientRefreshTokenId,
		byte[] newTokenHash,
		DateTime newExpiresAtUtc,string jti,DateTime accessTokenExpiresAtUtc,
		string? ipAddress,
		CancellationToken cancellationToken = default)
	{
		await using var conn = _connFactory.CreateConnection();
		await conn.OpenAsync(cancellationToken);

		var command = new CommandDefinition(
			commandText: "auth.RotateClientRefreshToken",
			parameters: new
			{
				PresentedTokenHash = presentedTokenHash,
				NewClientRefreshTokenID = newClientRefreshTokenId,
				NewTokenHash = newTokenHash,
				NewExpiresAtUtc = newExpiresAtUtc,
				Jti = jti,
				AccessTokenExpiresAtUtc = accessTokenExpiresAtUtc,
				IPAddress = ipAddress
			},
			commandType: CommandType.StoredProcedure,
			cancellationToken: cancellationToken);

		return await conn.ExecuteScalarAsync<int>(command);
	}
}
