
using ApplicationAuthentication.Entities;
using ApplicationAuthentication.Repositories.Interfaces;
using Dapper;
using GlobalAuth.Api.Data;

namespace ApplicationAuthentication.Repositories;

public class GroupRepository : IGroupRepository
{
	private readonly SqlConnectionFactory _databaseConnection;

	public GroupRepository(SqlConnectionFactory databaseConnection)
	{
		_databaseConnection = databaseConnection;
	}

	public async Task<IEnumerable<Group>> GetGroupsByUserIdAsync(
		string userId,
		string applicationId,
		CancellationToken cancellationToken = default)
	{
		const string sql = """
            SELECT
                g.GroupId,
                g.ApplicationId,
                g.GroupName,
                g.Description,
                g.IsActive,
                g.CreatedAt
            FROM dbo.Groups g
            INNER JOIN dbo.UserGroups ug
                ON g.GroupId = ug.GroupId
                AND g.ApplicationId = ug.ApplicationId
            WHERE ug.UserId = @UserId
                AND g.ApplicationId = @ApplicationId
                AND g.IsActive = 1;
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

		return await connection.QueryAsync<Group>(command);
	}
}
