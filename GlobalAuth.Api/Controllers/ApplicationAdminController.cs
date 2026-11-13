using GlobalAuth.Api.Constants;
using GlobalAuth.Api.Contracts;
using GlobalAuth.Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace GlobalAuth.Api.Controllers;

[ApiController]
[Route("api/admin/applications")]
public sealed class ApplicationAdminController : ControllerBase
{
	private const string AdminApplicationId = "AUTH_PLATFORM_ADMIN";

	private readonly ApplicationService _applicationService;

	public ApplicationAdminController(ApplicationService applicationService)
	{
		_applicationService = applicationService;
	}

	[HttpPut("{applicationId}/configuration")]
	[Authorize(Policy = "ApplicationUpdate")]
	public async Task<IActionResult> UpdateConfiguration(
		string applicationId,
		[FromBody] UpdateApplicationConfigurationRequest request,
		CancellationToken cancellationToken)
	{
		var updatedBy = User.FindFirst("sub")?.Value;

		try
		{
			var updated = await _applicationService.UpdateConfigurationAsync(
				applicationId,
				request.AllowMultipleUserSessions,
				request.MaxActiveUserSessions,
				request.IdleTimeoutMinutes,
				updatedBy ?? string.Empty,
				cancellationToken);

			if (!updated)
				return NotFound("Application not found.");

			return Ok(new
			{
				message = "Application configuration updated successfully."
			});
		}
		catch (ArgumentException ex)
		{
			return BadRequest(new { message = ex.Message });
		}
	}

	[HttpPost("{applicationId}/deactivate")]
	[Authorize(Policy = "ApplicationDeactivate")]
	public async Task<IActionResult> Deactivate(
		string applicationId,
		CancellationToken cancellationToken)
	{
		// Prevent accidental deactivation of the platform's own admin application.
		if (string.Equals(
			applicationId,
			AdminApplicationId,
			StringComparison.OrdinalIgnoreCase))
		{
			return BadRequest(
				"The GlobalAuth administration application cannot be deactivated through this API.");
		}

		var updatedBy = User.FindFirst("sub")?.Value;

		try
		{
			await _applicationService.DeactivateApplicationAsync(
				applicationId,
				updatedBy ?? string.Empty,
				cancellationToken);

			return Ok(new
			{
				message = "Application deactivated successfully."
			});
		}
		catch (ArgumentException ex)
		{
			return BadRequest(new { message = ex.Message });
		}
	}

	[HttpPost("{applicationId}/reactivate")]
	[Authorize(Policy = "ApplicationUpdate")]
	public async Task<IActionResult> Reactivate(
		string applicationId,
		CancellationToken cancellationToken)
	{
		var updatedBy = User.FindFirst("sub")?.Value;

		try
		{
			await _applicationService.ReactivateApplicationAsync(
				applicationId,
				updatedBy ?? string.Empty,
				cancellationToken);

			return Ok(new
			{
				message = "Application reactivated successfully."
			});
		}
		catch (ArgumentException ex)
		{
			return BadRequest(new { message = ex.Message });
		}
	}
}