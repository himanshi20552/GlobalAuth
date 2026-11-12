
using ApplicationAuthentication.Entities;
using ApplicationAuthentication.Repositories.Interfaces;
using Dapper;
using GlobalAuth.Api.Data;

namespace ApplicationAuthentication.Repositories
{
	public class UserRepository : IUserRepository
	{
		private readonly SqlConnectionFactory _databaseConnection;

		public UserRepository(SqlConnectionFactory databaseConnection)
		{
			_databaseConnection = databaseConnection;
		}

		public async Task<User?> GetByUserIdAsync(
			string userId,
			CancellationToken cancellationToken = default)
		{
			const string sql = """
                SELECT UserId, UserName, PasswordHash, IsActive, IsBlocked, CreatedAt
                FROM dbo.Users
                WHERE UserId = @UserId;
                """;

			var command = new CommandDefinition(
				commandText: sql,
				parameters: new { UserId = userId },
				cancellationToken: cancellationToken);

			using var connection = _databaseConnection.CreateConnection();

			return await connection.QueryFirstOrDefaultAsync<User>(command);
		}

		public async Task UpdatePasswordHashAsync(
			string userId,
			string newPasswordHash,
			CancellationToken cancellationToken = default)
		{
			const string sql = """
                UPDATE dbo.Users
                SET PasswordHash = @NewPasswordHash
                WHERE UserId = @UserId;
                """;

			var command = new CommandDefinition(
				commandText: sql,
				parameters: new
				{
					UserId = userId,
					NewPasswordHash = newPasswordHash
				},
				cancellationToken: cancellationToken);

			using var connection = _databaseConnection.CreateConnection();

			await connection.ExecuteAsync(command);
		}
	}
}
