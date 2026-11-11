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
                Set xact abort on;
                begin transaction;
                declare @NowUtc Datetime2=SYSUTCDATETIME();
                declare @IdleTimeoutMinutes int;
                declare @RowsInserted int=0;

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
                 and s.SubjectID = @SubjectID and s.StatusID = 1
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
        public async Task<RefreshTokenRotationResult> RotationAsync(byte[] presentedTokenHash, Guid newRefreshTokenId,
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
            var result = await conn.QuerySingleAsync<RefreshTokenRotationResult>(command);
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

	}
}
