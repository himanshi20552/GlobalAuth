using Dapper;
using GlobalAuth.Api.Data;
namespace GlobalAuth.Api.Repositories
{
    public sealed class ClientPermissionRepository
    {
        private readonly SqlConnectionFactory _connFactory;
		public ClientPermissionRepository(SqlConnectionFactory connFactory)
		{
			_connFactory = connFactory;
		}
		public async Task<IReadOnlyList<string>> GetActivePermissionsByClientAsync(string clientId, CancellationToken cancellationToken = default)
		{
			const string sql = """
				Select p.PermissionCode from auth.ClientPermissions cp 
				inner join auth.Permissions p on cp.PermissionID=p.PermissionID
				inner join auth.ClientCredentials c on cp.ClientID=c.ClientID
				where cp.ClientID=@ClientID and c.IsActive=1 and p.IsActive=1
				order by p.PermissionCode;

				""";
			await using var conn = _connFactory.CreateConnection();
			await conn.OpenAsync(cancellationToken);
			var command = new CommandDefinition(sql, new { ClientID = clientId }, cancellationToken: cancellationToken);
			var permissions = await conn.QueryAsync<string>(command);
			return permissions.AsList();
		}
	}
}
