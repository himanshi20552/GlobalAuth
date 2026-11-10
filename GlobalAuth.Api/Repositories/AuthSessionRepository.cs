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
		public async Task<IReadOnlyList<AuthSession>> GetActiveBySubjectAsync(string subjectType, string subjectId, string? applicationId, CancellationToken cancellationToken = default)
		{
			const string sql = """
				Select * from auth.AuthSessions where SubjectType=@SubjectType and SubjectID=@SubjectID
				and ( (@ApplicationID is null And ApplicationID is null) or ApplicationID=@ApplicationID )
				and RevokedAtUtc is null and ExpiresAtUtc>SYSUTCDATETIME()
				order by CreatedAtUtc Desc;
				""";
			await using var conn = _connFactory.CreateConnection();
			await conn.OpenAsync(cancellationToken);
			var command = new CommandDefinition(sql, new { SubjectType = subjectType, SubjectID = subjectId , ApplicationID = applicationId }, cancellationToken: cancellationToken);
			var sessions = await conn.QueryAsync<AuthSession>(command);
			return sessions.AsList();
		}

		//revoke a session
		public async Task RevokeAsync(Guid sessionId, string reason, CancellationToken cancellationToken = default) {
			const string sql = """
				    update auth.AuthSessions 
						 set RevokedAtUtc=SYSUTCDATETIME(),RevocationReason=@Reason
						 where SessionID=@SessionID and revokedAtUtc is null;
				""";
			await using var conn = _connFactory.CreateConnection();
			await conn.OpenAsync(cancellationToken);
			var command = new CommandDefinition(sql, new { SessionID = sessionId, Reason = reason }, cancellationToken: cancellationToken);
			await conn.ExecuteAsync(command);

		}
		//revoke all active sessions for a user or client
		public async Task RevokeAllActiveAsync(string subjectType, string subjectId, string? applicationId, string reason, CancellationToken cancellationToken = default)
		{
			const string sql = """
				 update auth.AuthSessions 
				 set RevokedAtUtc=SYSUTCDATETIME(),RevocationReason=@Reason
				 where SubjectType=@SubjectType and SubjectID=@SubjectID and 
				 ((@ApplicationID is null And ApplicationID is null) or ApplicationID=@ApplicationID)
				 and revokedAtUtc is null and ExpiresAtUtc>SYSUTCDATETIME();
				 """;
			await using var conn = _connFactory.CreateConnection();
			await conn.OpenAsync(cancellationToken);
			var command = new CommandDefinition(sql, new { SubjectType = subjectType, SubjectID = subjectId, ApplicationID = applicationId, Reason = reason }, cancellationToken: cancellationToken);
			await conn.ExecuteAsync(command);
		}
		//to create a new session in db for a user after checking apps session policy
		public async Task<SessionCreationResult> CreateUserSessionAsync(AuthSession session,CancellationToken cancellationToken = default)
		{
			const string procedure = "auth.CreateUserSession";
			await using var conn = _connFactory.CreateConnection();
			await conn.OpenAsync(cancellationToken);
			var command=new CommandDefinition( procedure,new{ session.SessionID,ApplicationID=session.ApplicationID, SubjectID= session.SubjectID, session.DeviceID, 
				session.IPAddress, session.UserAgent,session.ExpiresAtUtc },
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
		// to create a new session in db for a client
		public async Task<SessionCreationResult> CreateClientSessionAsync(AuthSession session, CancellationToken cancellationToken = default)
		{
			const string procedure = "auth.CreateClientSession";
			await using var conn = _connFactory.CreateConnection();
			await conn.OpenAsync(cancellationToken);
			var command = new CommandDefinition(procedure, new
			{
				session.SessionID,
				ClientID = session.SubjectID,
				session.DeviceID,
				session.IPAddress,
				session.UserAgent,
				session.ExpiresAtUtc
			},
				commandType: System.Data.CommandType.StoredProcedure,
				cancellationToken: cancellationToken);
			var result = await conn.QuerySingleAsync<int>(command);
			return result switch
			{
				0 => SessionCreationResult.Created,
				3 => SessionCreationResult.ClientInactive,
				_ => throw new InvalidOperationException("Unexpected result from CreateClientSession stored procedure.")

			};
		}
		//revoke a session if it belongs to the specified user/client
		//to provide a session specific logout functionality if needed
		public async Task<bool> RevokeOwnedAsync(Guid sessionId, string subjectType, string subjectId, string? applicationId,
			string reason, CancellationToken cancellationToken = default)
		{
			const string sql = """
				Update auth.AuthSessions set 
				RevokedAtUtc=SYSUTCDATETIME(),RevocationReason=@Reason
				where SessionID=@SessionID and SubjectID=@SubjectID and SubjectType=@SubjectType
				AND (( @ApplicationID is null and ApplicationID is null )
				or @ApplicationID=ApplicationID )
				and RevokedAtUtc is null and ExpiresAtUtc > SYSUTCDATETIME();
				""";
			await using var conn = _connFactory.CreateConnection();
			await conn.OpenAsync(cancellationToken);
			var command = new CommandDefinition(sql, new
			{
				SessionID = sessionId,
				SubjectType = subjectType,
				SubjectID = subjectId,
				ApplicationID = applicationId,
				Reason = reason
			}, cancellationToken:cancellationToken);
			var affectedRows = await conn.ExecuteAsync(command);
			return affectedRows == 1;
		}
	
	}
}
