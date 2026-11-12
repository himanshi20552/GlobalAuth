
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

	public async Task<IEnumerable<Permission>> GetPermissionsByUserIdAsync(
		string userId,
		string applicationId,
		CancellationToken cancellationToken = default)
	{
		const string sql = """
            SELECT DISTINCT
                p.PermissionId,
                p.ApplicationId,
                p.PermissionCode,
                p.PermissionName,
                p.Description,
                p.IsActive,
                p.CreatedAt
            FROM dbo.Permissions p
            INNER JOIN dbo.GroupPermissions gp
                ON p.PermissionId = gp.PermissionId
                AND p.ApplicationId = gp.ApplicationId
            INNER JOIN dbo.Groups g
                ON gp.GroupId = g.GroupId
                AND gp.ApplicationId = g.ApplicationId
            INNER JOIN dbo.UserGroups ug
                ON g.GroupId = ug.GroupId
                AND g.ApplicationId = ug.ApplicationId
            WHERE ug.UserId = @UserId
                AND g.IsActive = 1
                AND p.IsActive = 1
                AND ug.ApplicationId = @ApplicationId
                AND p.ApplicationId = @ApplicationId
                AND g.ApplicationId = @ApplicationId;
            """;

		var command = new CommandDefinition(
			commandText: sql,
			parameters: new
			{
				UserId = userId,
				ApplicationId = applicationId
			},
			cancellationToken: cancellationToken);

		using var connection = _databaseConnection.CreateConnection();

		return await connection.QueryAsync<Permission>(command);
	}
}
