
using System.Data;
using Dapper;
using GlobalAuth.Api.Data;

namespace GlobalAuth.Api.Repositories;

public sealed class ApplicationRepository
{
	private readonly SqlConnectionFactory _connFactory;

	public ApplicationRepository(SqlConnectionFactory connFactory)
	{
		_connFactory = connFactory;
	}

	public async Task DeactivateAsync(string applicationId,string updatedBy,CancellationToken cancellationToken = default)
	{
		const string procedure = "auth.DeactivateApplication";

		await using var conn = _connFactory.CreateConnection();
		await conn.OpenAsync(cancellationToken);

		var command = new CommandDefinition(
			procedure,
			new { ApplicationID = applicationId,UpdatedBy=updatedBy },
			commandType: CommandType.StoredProcedure,
			cancellationToken: cancellationToken
		);

		await conn.ExecuteAsync(command);
	}

	public async Task ReactivateAsync(
		string applicationId,string updatedBy,
		CancellationToken cancellationToken = default)
	{
		const string procedure = "auth.ReactivateApplication";

		await using var conn = _connFactory.CreateConnection();
		await conn.OpenAsync(cancellationToken);

		var command = new CommandDefinition(
			procedure,
			new { ApplicationID = applicationId,UpdatedBy=updatedBy },
			commandType: CommandType.StoredProcedure,
			cancellationToken: cancellationToken
		);

		await conn.ExecuteAsync(command);
	}
}
