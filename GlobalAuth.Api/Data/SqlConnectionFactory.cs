using Microsoft.Data.SqlClient;

namespace GlobalAuth.Api.Data;

public sealed class SqlConnectionFactory
{
	private readonly string _connectionString;
	public SqlConnectionFactory(IConfiguration config)
	{
		_connectionString =
			config.GetConnectionString("dbconn") ?? throw new InvalidOperationException("GlobalAuth database connection string is not configured.");
	}
	public SqlConnection CreateConnection()
	{
		return new SqlConnection(_connectionString);
	}
}