using ApplicationAuthentication.Entities;
using ApplicationAuthentication.Repositories.Interfaces;
using Dapper;
using GlobalAuth.Api.Data;

namespace ApplicationAuthentication.Repositories;

public class GroupRepository : IGroupRepository {
	private readonly SqlConnectionFactory _databaseConnection;
	public GroupRepository(SqlConnectionFactory databaseConnection) {
		_databaseConnection = databaseConnection; }
	public async Task<IEnumerable<Group>> GetGroupsByUserIdAsync(string userId, string applicationId)
	{
		const string sql = """
			SELECT
			g.GroupId,g.ApplicationId, g.GroupName, g.Description, g.IsActive, g.CreatedAt
			FROM Groups g
			INNER JOIN UserGroups ug
			     ON g.GroupId = ug.GroupId
			WHERE ug.UserId =@UserId
			    AND g.ApplicationId = @ApplicationId
			    AND g.IsActive =1;
			""";
		using var connection = _databaseConnection.CreateConnection();
		var groups = await connection.QueryAsync<Group>(sql, new { UserId = userId, ApplicationId = applicationId });
		return groups; 
	}

}
