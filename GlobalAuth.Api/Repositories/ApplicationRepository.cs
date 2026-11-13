
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
	public async Task<bool> UpdateConfigurationAsync(
	string applicationId,
	bool allowMultipleUserSessions,
	int maxActiveUserSessions,
	int idleTimeoutMinutes,
	string updatedBy,
	CancellationToken cancellationToken = default)
	{
		const string sql = """
        UPDATE auth.Applications
        SET
            AllowMultipleUserSessions = @AllowMultipleUserSessions,
            MaxActiveUserSessions = @MaxActiveUserSessions,
            IdleTimeoutMinutes = @IdleTimeoutMinutes,
            UpdatedAtUtc = SYSUTCDATETIME(),
            UpdatedBy = @UpdatedBy
        WHERE ApplicationID = @ApplicationID;
        """;

		await using var conn = _connFactory.CreateConnection();
		await conn.OpenAsync(cancellationToken);

		var command = new CommandDefinition(
			sql,
			new
			{
				ApplicationID = applicationId,
				AllowMultipleUserSessions = allowMultipleUserSessions,
				MaxActiveUserSessions = maxActiveUserSessions,
				IdleTimeoutMinutes = idleTimeoutMinutes,
				UpdatedBy = updatedBy
			},
			cancellationToken: cancellationToken
		);

		var affectedRows = await conn.ExecuteAsync(command);

		return affectedRows > 0;
	}
}
