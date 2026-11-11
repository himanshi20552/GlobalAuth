
using System.Net.Http.Headers;
using System.Net.Http.Json;

namespace GlobalAuth.Client.Services;

public sealed class SessionValidationClient
{
	private readonly HttpClient _httpClient;
	private readonly string _endpoint;

	public SessionValidationClient(HttpClient httpClient,string endpoint)
	{
		_httpClient = httpClient;
		_endpoint = endpoint;
	}

	public async Task<bool> ValidateSessionAsync(string accessToken,
		CancellationToken cancellationToken = default)
	{
		using var request = new HttpRequestMessage(
			HttpMethod.Post,_endpoint);

		request.Headers.Authorization =
			new AuthenticationHeaderValue("Bearer", accessToken);

		using var response = await _httpClient.SendAsync(request,
			cancellationToken);

		response.EnsureSuccessStatusCode();

		var result = await response.Content.ReadFromJsonAsync<SessionValidationResponse>(
			cancellationToken: cancellationToken);

		return result?.IsValid == true;
	}

	private sealed class SessionValidationResponse
	{
		public bool IsValid { get; set; }
	}
}
