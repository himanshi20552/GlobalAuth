using Dapper;
using GlobalAuth.Api.Data;
using GlobalAuth.Api.Models;

namespace GlobalAuth.Api.Repositories;

public sealed class AuthTokenIssuanceAuditRepository
{
	private readonly SqlConnectionFactory _connFactory;
	public AuthTokenIssuanceAuditRepository(SqlConnectionFactory connFactory)
	{
		_connFactory = connFactory;
	}
	public async Task CreateAsync(
		AuthTokenIssuanceAudit audit,
		CancellationToken cancellationToken = default)
	{
		const string sql = """
			    Insert into auth.AuthTokenIssuanceAudit ( Jti, SessionID, IssuanceType, IssuedAtUtc,ExpiresAtUtc,IpAddress,UserAgent,DeviceID)
						Values( @Jti, @SessionID , @IssuanceType, @IssuedAtUtc, @ExpiresAtUtc, @IpAddress, @UserAgent,
						@DeviceID);
			""";

		await using var conn = _connFactory.CreateConnection();
		await conn.OpenAsync(cancellationToken);
		var command = new CommandDefinition(sql,audit,cancellationToken: cancellationToken);
		await conn.ExecuteAsync(command);
	}
}