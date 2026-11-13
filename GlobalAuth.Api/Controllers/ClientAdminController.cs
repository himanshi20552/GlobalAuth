
using GlobalAuth.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace GlobalAuth.Api.Controllers;

[ApiController]
[Route("api/admin/clients")]
public sealed class ClientAdminController : ControllerBase
{
	private readonly ClientManagementService _clientManagementService;

	public ClientAdminController(
		ClientManagementService clientManagementService)
	{
		_clientManagementService = clientManagementService;
	}

	[HttpPost("{clientId}/deactivate")]
	[Authorize(Policy = "ClientDeactivate")]
	public async Task<IActionResult> Deactivate(
		string clientId,
		CancellationToken cancellationToken)
	{
		var updatedBy = User.FindFirst("sub")?.Value;

		try
		{
			await _clientManagementService.DeactivateClientAsync(
				clientId,
				updatedBy ?? string.Empty,
				cancellationToken);

			return Ok(new
			{
				message = "Client deactivated successfully."
			});
		}
		catch (ArgumentException ex)
		{
			return BadRequest(new { message = ex.Message });
		}
	}

	[HttpPost("{clientId}/reactivate")]
	[Authorize(Policy = "ClientUpdate")]
	public async Task<IActionResult> Reactivate(
		string clientId,
		CancellationToken cancellationToken)
	{
		var updatedBy = User.FindFirst("sub")?.Value;

		try
		{
			await _clientManagementService.ReactivateClientAsync(
				clientId,
				updatedBy ?? string.Empty,
				cancellationToken);

			return Ok(new
			{
				message = "Client reactivated successfully."
			});
		}
		catch (ArgumentException ex)
		{
			return BadRequest(new { message = ex.Message });
		}
	}

	[HttpPost("{clientId}/rotate-secret")]
	[Authorize(Policy = "ClientSecretRotate")]
	public async Task<IActionResult> RotateSecret(
		string clientId,
		CancellationToken cancellationToken)
	{
		var updatedBy = User.FindFirst("sub")?.Value;

		try
		{
			var newSecret =
				await _clientManagementService.RotateClientSecretAsync(
					clientId,
					updatedBy ?? string.Empty,
					cancellationToken);

			if (newSecret is null)
			{
				return NotFound(new
				{
					message = "Client not found."
				});
			}

			return Ok(new
			{
				clientId,
				clientSecret = newSecret,
				message = "Client secret rotated successfully. Store this secret securely; it will not be displayed again."
			});
		}
		catch (ArgumentException ex)
		{
			return BadRequest(new { message = ex.Message });
		}
	}

}
