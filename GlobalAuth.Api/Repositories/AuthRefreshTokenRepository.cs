using System.Data;
using Dapper;
using GlobalAuth.Api.Data;
using GlobalAuth.Api.Models;
using Microsoft.AspNetCore.Connections;
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
                Declare @NowUtc DateTime2=SYSUTCDATETIME();
                Insert into auth.AuthRefreshTokens(RefreshTokenID,SessionID,FamilyID,TokenHash,ExpiresAtUtc)
                Select @RefreshTokenID,s.SessionID,@FamilyID,@TokenHash,@ExpiresAtUtc from Auth.AuthSessions s
                with (UPDLOCK,HOLDLOCK) where s.SessionID=@SessionID
                and s.RevokedAtUtc is null and s.ExpiresAtUtc > @NowUtc
                 and @ExpiresAtUtc > @NowUtc and @ExpiresAtUtc <= s.ExpiresAtUtc;
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
           var rowsAffected= await conn.ExecuteAsync(command);
            return rowsAffected == 1;
        }
        public async Task<RefreshTokenRotationResult> RotationAsync(byte[] presentedTokenHash, Guid newRefreshTokenId,
            byte[] newTokenHash, DateTime newExpiresAtUtc, CancellationToken cancellationToken = default)
        {
            await using var conn = _connFactory.CreateConnection();
            await conn.OpenAsync(cancellationToken);
            var command = new CommandDefinition(commandText: "auth.RotateRefreshToken",
                parameters: new
                {
                    PresentedTokenHash = presentedTokenHash,
                    NewRefreshTokenID = newRefreshTokenId,
                    NewTokenHash = newTokenHash,
                    NewExpiresAtUtc = newExpiresAtUtc
                }, commandType: CommandType.StoredProcedure, cancellationToken: cancellationToken);
            var result = await conn.QuerySingleAsync<RefreshTokenRotationResult>(command);
            return result;
        }
		public async Task<RefreshTokenContext?> GetContextByTokenHashAsync(byte[] tokenHash,CancellationToken cancellationToken = default)
		{
			const string sql = """
        Select rt.SessionID, s.SubjectType,s.SubjectID,
            s.ApplicationID, s.ExpiresAtUtc AS SessionExpiresAtUtc, rt.ExpiresAtUtc AS TokenExpiresAtUtc,
            rt.UsedAtUtc,rt.RevokedAtUtc,s.RevokedAtUtc AS SessionRevokedAtUtc
        from auth.AuthRefreshTokens rt
        inner join auth.AuthSessions s
            on s.SessionID = rt.SessionID
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
