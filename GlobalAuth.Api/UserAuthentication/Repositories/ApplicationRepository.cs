using ApplicationAuthentication.Entities;
using ApplicationAuthentication.Repositories.Interfaces;
using Dapper;
using GlobalAuth.Api.Data;

namespace ApplicationAuthentication.Repositories;

public class ApplicationRepository : IApplicationRepository
{
	private readonly SqlConnectionFactory _databaseConnection;

	public ApplicationRepository(SqlConnectionFactory databaseConnection)
	{
		_databaseConnection = databaseConnection;
	}

	public async Task<Application?> GetByApplicationIdAsync(
		string applicationId,
		CancellationToken cancellationToken = default)
	{
		const string sql = """
            SELECT ApplicationId, ApplicationName, HashKey, IsActive, CreatedAt
            FROM Applications
            WHERE ApplicationId = @ApplicationId;
            """;

		var command = new CommandDefinition(
			commandText: sql,
			parameters: new { ApplicationId = applicationId },
			cancellationToken: cancellationToken);

		using var connection = _databaseConnection.CreateConnection();

		return await connection.QueryFirstOrDefaultAsync<Application>(command);
	}
}