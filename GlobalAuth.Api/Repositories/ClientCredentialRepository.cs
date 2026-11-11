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



	}
}
