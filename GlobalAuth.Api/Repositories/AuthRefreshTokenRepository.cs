using System.Data;
using Dapper;
using GlobalAuth.Api.Data;
using GlobalAuth.Api.Models;
namespace GlobalAuth.Api.Repositories
{
    public sealed class AuthRefreshTokenRepository
    {
        private readonly SqlConnectionFactory _connFactory;
        public AuthRefreshTokenRepository(SqlConnectionFactory connFactory) {
            _connFactory = connFactory;

        }
        public async Task<bool> CreateAsync(Guid refreshTokenId, Guid sessionId, Guid familyId, byte[] tokenHash,
            DateTime expiresAtUtc, CancellationToken cancellationToken = default)
        {
            const string sql = """
                Set xact_abort on;
                begin transaction;
                declare @NowUtc Datetime2=SYSUTCDATETIME();
                declare @ApplicationID nvarchar(100);
                declare @IdleTimeoutMinutes int;
                declare @RowsInserted int=0;

                select @ApplicationID=ApplicationID from
                auth.AuthSessions where SessionID=@SessionID;

                Select @IdleTimeoutMinutes=IdleTimeoutMinutes
                from auth.Applications with (UPDLOCK, HOLDLOCK)
                where ApplicationID = @ApplicationID and IsActive = 1;

                if @IdleTimeoutMinutes is not null 
                begin 
                insert into auth.AuthRefreshTokens
                ( RefreshTokenID,SessionID,FamilyID,TokenHash,ExpiresAtUtc)
                select @RefreshTokenID, s.SessionID,@FamilyID,@TokenHash,@ExpiresAtUtc
                from auth.AuthSessions s with (UPDLOCK,HOLDLOCK)
                where s.SessionID = @SessionID and s.ApplicationID = @ApplicationID
                 and s.StatusID = 1
                 and s.RevokedAtUtc IS NULL and s.LastActivityAtUtc > DATEADD(MINUTE, -@IdleTimeoutMinutes, @NowUtc)
                 and @ExpiresAtUtc > @NowUtc;
                 set @RowsInserted = @@ROWCOUNT;
                end;
                commit transaction;
                select @RowsInserted;
                """;
            await using var conn = _connFactory.CreateConnection();
            await conn.OpenAsync(cancellationToken);
            var command = new CommandDefinition(sql, new
            {
                RefreshTokenID = refreshTokenId,
                SessionID = sessionId,
                FamilyID = familyId,
                TokenHash = tokenHash,
                ExpiresAtUtc = expiresAtUtc
            }, cancellationToken: cancellationToken);
           var rowsAffected= await conn.ExecuteScalarAsync<int>(command);
            return rowsAffected == 1;
        }
        public async Task<int> RotationAsync(byte[] presentedTokenHash, Guid newRefreshTokenId,
            byte[] newTokenHash, DateTime newExpiresAtUtc, string? jti, DateTime? accessTokenExpiresAtUtc,
            string? ipAddress,CancellationToken cancellationToken = default)
        {
            await using var conn = _connFactory.CreateConnection();
            await conn.OpenAsync(cancellationToken);
            var command = new CommandDefinition(commandText: "auth.RotateRefreshToken",
                parameters: new
                {
                    PresentedTokenHash = presentedTokenHash,
                    NewRefreshTokenID = newRefreshTokenId,
                    NewTokenHash = newTokenHash,
                    NewExpiresAtUtc = newExpiresAtUtc,
                    Jti=jti,
                    AccessTokenExpiresAtUtc=accessTokenExpiresAtUtc,
                    IPAddress=ipAddress
                }, commandType: CommandType.StoredProcedure, cancellationToken: cancellationToken);
            var result = await conn.ExecuteScalarAsync<int>(command);
            return result;
        }
		public async Task<RefreshTokenContext?> GetContextByTokenHashAsync(byte[] tokenHash,CancellationToken cancellationToken = default)
		{
			const string sql = """
        Select rt.SessionID,s.SubjectID,
            s.ApplicationID, s.StatusID as SessionStatusID,s.LastActivityAtUtc,a.IdleTimeoutMinutes,
            a.IsActive as ApplicationIsActive,
            rt.ExpiresAtUtc AS TokenExpiresAtUtc,
            rt.UsedAtUtc,rt.RevokedAtUtc,s.RevokedAtUtc AS SessionRevokedAtUtc
        from auth.AuthRefreshTokens rt
        inner join auth.AuthSessions s
            on s.SessionID = rt.SessionID
            inner join auth.Applications a
            on a.ApplicationID=s.ApplicationID
        where rt.TokenHash = @TokenHash;
        """;
			await using var connection = _connFactory.CreateConnection();
			return await connection.QuerySingleOrDefaultAsync<RefreshTokenContext>(
				new CommandDefinition(sql,new { TokenHash = tokenHash },cancellationToken: cancellationToken
				)
			);
		}



		public async Task<bool> RevokeSessionAndRefreshTokensAsync(
			byte[] tokenHash,
			string revocationSource,
			CancellationToken cancellationToken = default)
		{
			// Find the session associated with the presented token.
			const string findSessionSql = """
        SELECT SessionID
        FROM auth.AuthRefreshTokens
        WHERE TokenHash = @TokenHash;
        """;

			await using var connection = _connFactory.CreateConnection();
			await connection.OpenAsync(cancellationToken);

			var sessionId = await connection.QuerySingleOrDefaultAsync<Guid?>(
				new CommandDefinition(
					findSessionSql,
					new { TokenHash = tokenHash },
					cancellationToken: cancellationToken));

			if (!sessionId.HasValue)
				return false;

			await using var transaction =
				await connection.BeginTransactionAsync(
					IsolationLevel.ReadCommitted,
					cancellationToken);

			try
			{
				// Get the application's ID associated with this session.
				const string getApplicationSql = """
            SELECT ApplicationID
            FROM auth.AuthSessions
            WHERE SessionID = @SessionID;
            """;

				var applicationId =
					await connection.QuerySingleOrDefaultAsync<string>(
						new CommandDefinition(
							getApplicationSql,
							new { SessionID = sessionId.Value },
							transaction: transaction,
							cancellationToken: cancellationToken));

				if (string.IsNullOrWhiteSpace(applicationId))
				{
					await transaction.CommitAsync(cancellationToken);
					return false;
				}

				// 1. Lock the application.
				const string lockApplicationSql = """
            SELECT ApplicationID
            FROM auth.Applications WITH (HOLDLOCK)
            WHERE ApplicationID = @ApplicationID;
            """;

				var lockedApplicationId =
					await connection.QuerySingleOrDefaultAsync<string>(
						new CommandDefinition(
							lockApplicationSql,
							new { ApplicationID = applicationId },
							transaction: transaction,
							cancellationToken: cancellationToken));

				if (lockedApplicationId is null)
				{
					await transaction.CommitAsync(cancellationToken);
					return false;
				}

				// 2. Lock the session.
				const string lockSessionSql = """
            SELECT ApplicationID
            FROM auth.AuthSessions WITH (UPDLOCK, HOLDLOCK)
            WHERE SessionID = @SessionID;
            """;

				var lockedSessionApplicationId =
					await connection.QuerySingleOrDefaultAsync<string>(
						new CommandDefinition(
							lockSessionSql,
							new { SessionID = sessionId.Value },
							transaction: transaction,
							cancellationToken: cancellationToken));

				if (!string.Equals(
					lockedSessionApplicationId,
					applicationId,
					StringComparison.Ordinal))
				{
					await transaction.CommitAsync(cancellationToken);
					return false;
				}

				// 3. Lock and verify the presented refresh token.
				const string lockTokenSql = """
            SELECT SessionID
            FROM auth.AuthRefreshTokens WITH (UPDLOCK, HOLDLOCK)
            WHERE TokenHash = @TokenHash
              AND SessionID = @SessionID;
            """;

				var confirmedSessionId =
					await connection.QuerySingleOrDefaultAsync<Guid?>(
						new CommandDefinition(
							lockTokenSql,
							new
							{
								TokenHash = tokenHash,
								SessionID = sessionId.Value
							},
							transaction: transaction,
							cancellationToken: cancellationToken));

				if (!confirmedSessionId.HasValue)
				{
					await transaction.CommitAsync(cancellationToken);
					return false;
				}

				// Revoke the session and every refresh token belonging to it.
				const string revokeSql = """
            DECLARE @NowUtc DATETIME2 = SYSUTCDATETIME();

            UPDATE auth.AuthSessions
            SET
                StatusID = 2,
                RevokedAtUtc = @NowUtc,
                RevocationSource = @RevocationSource
            WHERE SessionID = @SessionID
              AND StatusID = 1
              AND RevokedAtUtc IS NULL;

            UPDATE auth.AuthRefreshTokens
            SET RevokedAtUtc = @NowUtc
            WHERE SessionID = @SessionID
              AND RevokedAtUtc IS NULL;
            """;

				await connection.ExecuteAsync(
					new CommandDefinition(
						revokeSql,
						new
						{
							SessionID = sessionId.Value,
							RevocationSource = revocationSource
						},
						transaction: transaction,
						cancellationToken: cancellationToken));

				await transaction.CommitAsync(cancellationToken);
				return true;
			}
			catch
			{
				try
				{
					await transaction.RollbackAsync(CancellationToken.None);
				}
				catch
				{
					// Preserve the original exception.
				}

				throw;
			}
		}



	}
}
