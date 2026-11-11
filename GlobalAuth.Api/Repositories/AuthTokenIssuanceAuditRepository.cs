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
	public async Task CreateAsync(AuthTokenIssuanceAudit audit,CancellationToken cancellationToken = default)
	{
		const string sql = """
			    Insert into auth.AuthTokenIssuanceAudit ( Jti,PrincipalType,SubjectID, SessionID, IssuanceType, IssuedAtUtc,IpAddress)
						Values( @Jti,@PricipalType,@SubjectID, @SessionID , @IssuanceType, @IssuedAtUtc, @IpAddress);
			""";

		await using var conn = _connFactory.CreateConnection();
		await conn.OpenAsync(cancellationToken);
		var command = new CommandDefinition(sql,audit,cancellationToken: cancellationToken);
		await conn.ExecuteAsync(command);
	}
}