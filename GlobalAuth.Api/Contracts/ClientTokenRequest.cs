using System.ComponentModel.DataAnnotations;
namespace GlobalAuth.Api.Contracts;
public sealed class ClientTokenRequest
{
	[Required]
	[StringLength(100)]
	public string ClientId { get; set; } = string.Empty;

	[Required]
	[StringLength(512)]
	public string ClientSecret { get; set; } = string.Empty;
}