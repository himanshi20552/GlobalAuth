
using System.Net.Http.Json;
using EmployeePortalDemo.Models.Requests;
using EmployeePortalDemo.Models.Responses;

namespace EmployeePortalDemo.Services;

public class AuthenticationApiClient
{
	private readonly HttpClient _httpClient;
	private readonly IConfiguration _configuration;
	public AuthenticationApiClient(HttpClient httpClient, IConfiguration configuration) //constructor dependency injection
	{
		_httpClient = httpClient;
		_configuration = configuration;
	}

	public async Task<LoginResponse?> LoginAsync(string userId, string password,
		CancellationToken cancellationToken = default)
	{
		var request = new LoginRequest
		{
			ApplicationId = _configuration["AuthenticationApi:ApplicationId"]
			?? throw new InvalidOperationException("Application ID is not configured."),

			HashKey = _configuration["AuthenticationApi:HashKey"]
			?? throw new InvalidOperationException("Application Hash Key is not configured."),

			UserId = userId,
			Password = password
		};
		using var response = await _httpClient.PostAsJsonAsync("api/Authentication/login",
			request, cancellationToken);
		response.EnsureSuccessStatusCode();
		return await response.Content.ReadFromJsonAsync<LoginResponse>(cancellationToken: cancellationToken);
	}

}
