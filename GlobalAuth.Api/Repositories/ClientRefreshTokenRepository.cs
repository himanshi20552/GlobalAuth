
using System.Data;
using Dapper;
using GlobalAuth.Api.Data;
using GlobalAuth.Api.Models;

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

	public async Task<ClientRefreshTokenContext?> GetContextByTokenHashAsync(byte[] tokenHash,
		CancellationToken cancellationToken = default)
	{
		const string sql = """
        select rt.ClientID, rt.FamilyID,rt.ExpiresAtUtc AS TokenExpiresAtUtc,rt.UsedAtUtc,
            rt.RevokedAtUtc,c.IsActive AS ClientIsActive
        from auth.AuthClientRefreshTokens rt
        inner join auth.ClientCredentials c
        on c.ClientID = rt.ClientID
        where rt.TokenHash = @TokenHash;
        """;
		await using var conn = _connFactory.CreateConnection();
		await conn.OpenAsync(cancellationToken);
		return await conn.QuerySingleOrDefaultAsync<ClientRefreshTokenContext>(
			new CommandDefinition(sql,new { TokenHash = tokenHash },cancellationToken: cancellationToken));
	}

	public async Task RevokeFamilyAsync(string clientId,Guid familyId,CancellationToken cancellationToken = default)
	{
		const string sql = """
        update auth.AuthClientRefreshTokens
        set RevokedAtUtc = COALESCE(RevokedAtUtc, SYSUTCDATETIME())
        where ClientID = @ClientID
          and FamilyID = @FamilyID;
        """;
		await using var conn = _connFactory.CreateConnection();
		await conn.OpenAsync(cancellationToken);
		await conn.ExecuteAsync(new CommandDefinition(sql,new {ClientID = clientId,FamilyID = familyId},
				cancellationToken: cancellationToken));
	}
}
