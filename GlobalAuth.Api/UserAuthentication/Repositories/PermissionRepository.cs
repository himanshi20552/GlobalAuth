using ApplicationAuthentication.Entities;
using ApplicationAuthentication.Repositories.Interfaces;
using Dapper;
using GlobalAuth.Api.Data;

namespace ApplicationAuthentication.Repositories;

public class PermissionRepository : IPermissionRepository
{
	private readonly SqlConnectionFactory _databaseConnection;
	public PermissionRepository(SqlConnectionFactory databaseConnection)
	{
		_databaseConnection = databaseConnection;
	}
	public async Task<IEnumerable<Permission>> GetPermissionsByUserIdAsync(string userId, string applicationId)
	{
		const string sql = """
			SELECT DISTINCT p.PermissionId,p.ApplicationId, p.PermissionCode, p.PermissionName, p.Description, p.IsActive, p.CreatedAt
			FROM Permissions p
			INNER JOIN GroupPermissions gp
			    ON p.PermissionId = gp.PermissionId
				AND p.ApplicationId = gp.ApplicationId
			INNER JOIN Groups g
			    ON gp.GroupId = g.GroupId
				AND gp.ApplicationId = g.ApplicationId
			INNER JOIN UserGroups ug
			    ON g.GroupId = ug.GroupId
				AND g.ApplicationId = ug.ApplicationId
			WHERE ug.UserId = @UserId
			  AND g.IsActive = 1
			  AND p.IsActive = 1
			  AND ug.ApplicationId = @ApplicationId
			  AND p.ApplicationId = @ApplicationId;
			""";
		using var connection = _databaseConnection.CreateConnection();
		var permissions = await connection.QueryAsync<Permission>(sql, new { UserId = userId, ApplicationId = applicationId });
		return permissions;

	}
}
