using Dapper;
using GlobalAuth.Api.Data;
using GlobalAuth.Api.Models;
namespace GlobalAuth.Api.Repositories
{
    public sealed class AuthSessionRepository
    {
        private readonly SqlConnectionFactory _connFactory;
        public AuthSessionRepository(SqlConnectionFactory connFactory)
		{
			_connFactory = connFactory;
		}
		
		//to retrieve a session by its id from db
		public async Task<AuthSession?> GetByIdAsync(Guid sessionId, CancellationToken cancellationToken = default)
		{
			const string sql = """
				Select * from auth.AuthSessions where SessionID=@SessionID;
				""";
			await using var conn = _connFactory.CreateConnection();
			await conn.OpenAsync(cancellationToken);
			var command = new CommandDefinition(sql, new { SessionID = sessionId }, cancellationToken: cancellationToken);
			return await conn.QuerySingleOrDefaultAsync<AuthSession>(command);

		}
		//retrieve active sessions for a user or client
		public async Task<IReadOnlyList<AuthSession>> GetActiveBySubjectAsync( string subjectId, string applicationId, CancellationToken cancellationToken = default)
		{
			const string sql = """
				Select * from auth.AuthSessions s inner join auth.Applications a
				on a.ApplicationID=s.ApplicationID where s.SubjectID=@SubjectID
				and s.ApplicationID=@ApplicationID and s.StatusID=1
				and s.RevokedAtUtc is null and a.IsActive=1 
				and s.LastActivityAtUtc> DateAdd(Minute, -a.IdleTimeoutMinutes, SYSUTCDATETIME())
				order by s.CreatedAtUtc desc;
				""";
			await using var conn = _connFactory.CreateConnection();
			await conn.OpenAsync(cancellationToken);
			var command = new CommandDefinition(sql, new { SubjectID = subjectId , ApplicationID = applicationId }, cancellationToken: cancellationToken);
			var sessions = await conn.QueryAsync<AuthSession>(command);
			return sessions.AsList();
		}

		//revoke a session
		public async Task RevokeAsync(Guid sessionId, string revocationSource, CancellationToken cancellationToken = default) {
			const string sql = """
				    update auth.AuthSessions 
						 set StatusID=2, RevokedAtUtc=SYSUTCDATETIME(),RevocationSource=@RevocationSource
						 where SessionID=@SessionID and StatusID=1 and revokedAtUtc is null;
				""";
			await using var conn = _connFactory.CreateConnection();
			await conn.OpenAsync(cancellationToken);
			var command = new CommandDefinition(sql, new { SessionID = sessionId, RevocationSource = revocationSource }, cancellationToken: cancellationToken);
			await conn.ExecuteAsync(command);

		}
		//revoke all active sessions for a user or client
		public async Task RevokeAllActiveAsync( string subjectId, string applicationId, string revocationSource, CancellationToken cancellationToken = default)
		{
			const string sql = """
				 update auth.AuthSessions 
				 set StatusID=2,RevokedAtUtc=SYSUTCDATETIME(),RevocationSource=@RevocationSource
				 where SubjectID=@SubjectID and 
				 ApplicationID=@ApplicationID
				 and RevokedAtUtc is null and StatusID=1;
				 """;
			await using var conn = _connFactory.CreateConnection();
			await conn.OpenAsync(cancellationToken);
			var command = new CommandDefinition(sql, new { SubjectID = subjectId, ApplicationID = applicationId,
				RevocationSource = revocationSource }, cancellationToken: cancellationToken);
			await conn.ExecuteAsync(command);
		}
		//to create a new session in db for a user after checking apps session policy
		public async Task<SessionCreationResult> CreateUserSessionAsync(AuthSession session,CancellationToken cancellationToken = default)
		{
			const string procedure = "auth.CreateUserSession";
			await using var conn = _connFactory.CreateConnection();
			await conn.OpenAsync(cancellationToken);
			var command=new CommandDefinition( procedure,new{ session.SessionID,ApplicationID=session.ApplicationID, SubjectID= session.SubjectID },
				commandType:System.Data.CommandType.StoredProcedure,
				cancellationToken: cancellationToken);
			var result = await conn.QuerySingleAsync<int>(command);
			return result switch
			{
				0 => SessionCreationResult.Created,
				1 => SessionCreationResult.SessionLimitReached,
				2 => SessionCreationResult.ApplicationInactive,
				_ => throw new InvalidOperationException("Unexpected result from CreateUserSession stored procedure.")
			};

		}
	
		//revoke a session if it belongs to the specified user/client
		//to provide a session specific logout functionality if needed
		public async Task<bool> RevokeOwnedAsync(Guid sessionId,string subjectId, string applicationId,
			string revocationSource, CancellationToken cancellationToken = default)
		{
			const string sql = """
				Update auth.AuthSessions set 
				StatusID=2,RevokedAtUtc=SYSUTCDATETIME(),RevocationSource=@RevocationSource
				where SessionID=@SessionID and SubjectID=@SubjectID 
				And @ApplicationID=ApplicationID 
				and RevokedAtUtc is null and StatusID=1;
				""";
			await using var conn = _connFactory.CreateConnection();
			await conn.OpenAsync(cancellationToken);
			var command = new CommandDefinition(sql, new
			{
				SessionID = sessionId,
				SubjectID = subjectId,
				ApplicationID = applicationId,
				RevocationSource = revocationSource
			}, cancellationToken:cancellationToken);
			var affectedRows = await conn.ExecuteAsync(command);
			return affectedRows == 1;
		}
	
	}
}
