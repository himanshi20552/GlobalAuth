using System.ComponentModel.DataAnnotations;

namespace ApplicationAuthentication.DTOs.Requests;

public sealed class ChangePasswordRequestDto
{
	[Required]
	public string CurrentPassword { get; set; } = string.Empty;

	[Required]
	public string NewPassword { get; set; } = string.Empty;
}