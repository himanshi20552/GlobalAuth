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
        public async Task<User?> GetByUserIdAsync(string userId)
        {
            const string sql = """
                
                SELECT UserId, UserName, PasswordHash,IsActive,IsBlocked,CreatedAt 
                FROM Users
                WHERE UserId = @UserId;
                
                """; //updates the existing employee password hash.
            using var connection = _databaseConnection.CreateConnection();
            return await connection.QueryFirstOrDefaultAsync<User>(sql, new { userId = userId });
        }

        public async Task UpdatePasswordHashAsync(string userId, string newPasswordHash)
		{
			const string sql = """
                
                UPDATE Users
                SET PasswordHash = @NewPasswordHash
                WHERE UserId = @UserId;
                
                """;
			using var connection = _databaseConnection.CreateConnection();
			await connection.ExecuteAsync(sql, new { UserId = userId, NewPasswordHash = newPasswordHash });
		}
	}
}
