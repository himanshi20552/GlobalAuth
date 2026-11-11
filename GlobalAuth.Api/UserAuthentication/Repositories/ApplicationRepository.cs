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
	public async Task<Application?> GetByApplicationIdAsync(string applicationId) {
		const string sql = """
			SELECT ApplicationId, ApplicationName, HashKey,IsActive,CreatedAt
			FROM Applications
			WHERE ApplicationId = @ApplicationId;
			""";
		using var connection = _databaseConnection.CreateConnection();
		var application = await connection.QueryFirstOrDefaultAsync<Application>(sql, new { ApplicationId = applicationId });

		return application;
	}
}
