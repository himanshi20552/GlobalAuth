using System.Data;
using Dapper;
using GlobalAuth.Api.Data;
using GlobalAuth.Api.Models;
namespace GlobalAuth.Api.Repositories
{
    public sealed class ClientCredentialRepository
    {
        private readonly SqlConnectionFactory _connFactory;
        public ClientCredentialRepository(SqlConnectionFactory connFactory) {
			_connFactory = connFactory;

		}
        public async Task<byte[]?> GetActiveClientSecretHashAsync(string clientId, CancellationToken cancellationToken = default)
        {
            const string sql = """
                Select ClientSecretHash from auth.ClientCredentials where ClientID=@ClientID and IsActive=1;
                """;
            await using var conn=_connFactory.CreateConnection();
            await conn.OpenAsync(cancellationToken);
            var command = new CommandDefinition(sql, new { ClientID = clientId }, cancellationToken: cancellationToken);
            return await conn.QuerySingleOrDefaultAsync<byte[]>(command);

		}

		public async Task DeactivateAsync(
			string clientId, string updatedBy,
			CancellationToken cancellationToken = default)
		{
			const string procedure = "auth.DeactivateClient";

			await using var conn = _connFactory.CreateConnection();
			await conn.OpenAsync(cancellationToken);

			var command = new CommandDefinition(
				procedure,
				new { ClientID = clientId , UpdatedBy=updatedBy},
				commandType: CommandType.StoredProcedure,
				cancellationToken: cancellationToken
			);

			await conn.ExecuteAsync(command);
		}

		public async Task ReactivateAsync(
			string clientId,string updatedBy,
			CancellationToken cancellationToken = default)
		{
			const string procedure = "auth.ReactivateClient";

			await using var conn = _connFactory.CreateConnection();
			await conn.OpenAsync(cancellationToken);

			var command = new CommandDefinition(
				procedure,
				new { ClientID = clientId, UpdatedBy=updatedBy },
				commandType: CommandType.StoredProcedure,
				cancellationToken: cancellationToken
			);

			await conn.ExecuteAsync(command);
		}


		public async Task<bool> RotateSecretAsync(
			string clientId,
			byte[] newSecretHash,
			string updatedBy,
			CancellationToken cancellationToken = default)
		{
			const string sql = """
        BEGIN TRY
            BEGIN TRANSACTION;

            DECLARE @ClientExists BIT = 0;

            -- Lock the client row so concurrent credential operations
            -- for this client are serialized.
            SELECT @ClientExists = 1
            FROM auth.ClientCredentials WITH (UPDLOCK, HOLDLOCK)
            WHERE ClientID = @ClientID;

            IF @ClientExists = 0
            BEGIN
                COMMIT TRANSACTION;
                SELECT CAST(0 AS INT);
                RETURN;
            END;

            -- Update the client secret hash.
            UPDATE auth.ClientCredentials
            SET
                ClientSecretHash = @NewSecretHash,
                UpdatedAtUtc = SYSUTCDATETIME(),
                UpdatedBy = @UpdatedBy
            WHERE ClientID = @ClientID;

            -- Revoke every refresh token record that has not
            -- already been revoked, including tokens in older families.
            UPDATE auth.AuthClientRefreshTokens
            SET RevokedAtUtc = SYSUTCDATETIME()
            WHERE ClientID = @ClientID
              AND RevokedAtUtc IS NULL;

            COMMIT TRANSACTION;

            SELECT CAST(1 AS INT);
        END TRY
        BEGIN CATCH
            IF @@TRANCOUNT > 0
                ROLLBACK TRANSACTION;

            THROW;
        END CATCH;
        """;

			await using var conn = _connFactory.CreateConnection();
			await conn.OpenAsync(cancellationToken);

			var command = new CommandDefinition(
				sql,
				new
				{
					ClientID = clientId,
					NewSecretHash = newSecretHash,
					UpdatedBy = updatedBy
				},
				cancellationToken: cancellationToken);

			var result = await conn.QuerySingleAsync<int>(command);

			return result == 1;
		}




	}
}
