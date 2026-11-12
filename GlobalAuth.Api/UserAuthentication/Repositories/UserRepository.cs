
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

		public async Task<bool> ChangePasswordAndRevokeSessionsAsync(string userId,string applicationId,Guid currentSessionId,
			string currentPasswordHash,string newPasswordHash,string revocationSource,
			CancellationToken cancellationToken = default)
		{
			const string sql = """
        SET NOCOUNT ON;
        SET XACT_ABORT ON;

        BEGIN TRY
            BEGIN TRANSACTION;

            DECLARE @NowUtc DATETIME2 = SYSUTCDATETIME();
            DECLARE @LockedApplicationID NVARCHAR(100);

            -- 1. Lock and verify the application.
            SELECT @LockedApplicationID = ApplicationID
            FROM auth.Applications WITH (HOLDLOCK)
            WHERE ApplicationID = @ApplicationID
              AND IsActive = 1;

            IF @LockedApplicationID IS NULL
            BEGIN
                ROLLBACK TRANSACTION;
                SELECT CAST(0 AS BIT);
                RETURN;
            END;

            -- 2. Lock all sessions belonging to this user
            -- in the current application.
            DECLARE @SessionIds TABLE
            (
                SessionID UNIQUEIDENTIFIER PRIMARY KEY
            );

            INSERT INTO @SessionIds (SessionID)
            SELECT SessionID
            FROM auth.AuthSessions WITH (UPDLOCK, HOLDLOCK)
            WHERE SubjectID = @UserID
              AND ApplicationID = @ApplicationID;

            -- 3. Ensure the current session is still active.
            IF NOT EXISTS
            (
                SELECT 1
                FROM auth.AuthSessions s
                INNER JOIN @SessionIds ids
                    ON ids.SessionID = s.SessionID
                WHERE s.SessionID = @CurrentSessionID
                  AND s.StatusID = 1
                  AND s.RevokedAtUtc IS NULL
            )
            BEGIN
                ROLLBACK TRANSACTION;
                SELECT CAST(0 AS BIT);
                RETURN;
            END;

            -- 4. Update the password only if the old hash
            -- still matches the one verified by the service.
            UPDATE dbo.Users
            SET PasswordHash = @NewPasswordHash
            WHERE UserId = @UserID
              AND CONVERT(VARBINARY(MAX), PasswordHash) =
                  CONVERT(VARBINARY(MAX), @CurrentPasswordHash);

            IF @@ROWCOUNT <> 1
            BEGIN
                ROLLBACK TRANSACTION;
                SELECT CAST(0 AS BIT);
                RETURN;
            END;

            -- 5. Revoke all active sessions in this application.
            UPDATE s
            SET
                StatusID = 2,
                RevokedAtUtc = @NowUtc,
                RevocationSource = @RevocationSource
            FROM auth.AuthSessions s
            INNER JOIN @SessionIds ids
                ON ids.SessionID = s.SessionID
            WHERE s.StatusID = 1
              AND s.RevokedAtUtc IS NULL;

            -- 6. Revoke refresh tokens belonging to
            -- all sessions in this application.
            UPDATE rt
            SET RevokedAtUtc = @NowUtc
            FROM auth.AuthRefreshTokens rt
            INNER JOIN @SessionIds ids
                ON ids.SessionID = rt.SessionID
            WHERE rt.RevokedAtUtc IS NULL;

            COMMIT TRANSACTION;

            SELECT CAST(1 AS BIT);
        END TRY
        BEGIN CATCH
            IF @@TRANCOUNT > 0
                ROLLBACK TRANSACTION;

            THROW;
        END CATCH;
        """;

			using var connection = _databaseConnection.CreateConnection();

			await connection.OpenAsync(cancellationToken);

			var command = new CommandDefinition(
				sql,
				new
				{
					UserID = userId,
					ApplicationID = applicationId,
					CurrentSessionID = currentSessionId,
					CurrentPasswordHash = currentPasswordHash,
					NewPasswordHash = newPasswordHash,
					RevocationSource = revocationSource
				},
				cancellationToken: cancellationToken);

			return await connection.ExecuteScalarAsync<bool>(command);
		}

	}
}
