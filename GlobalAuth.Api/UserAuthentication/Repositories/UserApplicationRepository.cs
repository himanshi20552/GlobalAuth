using ApplicationAuthentication.Repositories.Interfaces;
using Dapper;
using GlobalAuth.Api.Data;

namespace ApplicationAuthentication.Repositories;

public class UserApplicationRepository : IUserApplicationRepository
{
	private readonly SqlConnectionFactory _databaseConnection;
	public UserApplicationRepository(SqlConnectionFactory databaseConnection)
	{
		_databaseConnection = databaseConnection;
	}
	public async Task<bool> IsUserAssignedToApplicationAsync(string userId, string applicationId)
	{
		const string sql = @"
			SELECT COUNT(1) 
			FROM UserApplications
			WHERE UserId = @UserId AND ApplicationId = @ApplicationId AND IsActive = 1;
		";
		using var connection = _databaseConnection.CreateConnection();
		var count = await connection.ExecuteScalarAsync<int>(sql, new { UserId = userId, ApplicationId = applicationId });
		return count > 0;
	}
}
