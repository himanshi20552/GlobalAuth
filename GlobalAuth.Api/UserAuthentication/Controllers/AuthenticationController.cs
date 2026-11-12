using ApplicationAuthentication.Authentication.Interfaces;
using ApplicationAuthentication.DTOs.Requests;
using ApplicationAuthentication.Services.Interfaces;
using GlobalAuth.Api.Constants;
using Microsoft.AspNetCore.Authorization;
using GlobalAuth.Api.Contracts;
using GlobalAuth.Api.Services;

using Microsoft.AspNetCore.Mvc;

namespace ApplicationAuthentication.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthenticationController : ControllerBase
{
	private readonly IAuthenticationService _authenticationService;
	private readonly IApplicationValidationService _applicationValidationService;
	private readonly IUserAuthorizationProvider _userAuthorizationProvider;
	private readonly IUserApplicationAccessService _userApplicationAccessService;
	private readonly ITokenIssuanceService _tokenIssuanceService;
	private readonly IPasswordChangeService _passwordChangeService;

	public AuthenticationController(
		IAuthenticationService authenticationService,
		IApplicationValidationService applicationValidationService,
		IUserAuthorizationProvider userAuthorizationProvider,
		IUserApplicationAccessService userApplicationAccessService,
		IPasswordChangeService passwordChangeService,
		ITokenIssuanceService tokenIssuanceService)
	{
		_authenticationService = authenticationService;
		_applicationValidationService = applicationValidationService;
		_userAuthorizationProvider = userAuthorizationProvider;
		_userApplicationAccessService = userApplicationAccessService;
		_passwordChangeService = passwordChangeService;
		_tokenIssuanceService = tokenIssuanceService;
	}

	[HttpPost("login")]
	public async Task<IActionResult> Login(
		[FromBody] LoginRequestDto request,
		CancellationToken cancellationToken)
	{
		if (string.IsNullOrWhiteSpace(request.ApplicationId) ||
			string.IsNullOrWhiteSpace(request.HashKey) ||
			string.IsNullOrWhiteSpace(request.UserId) ||
			string.IsNullOrWhiteSpace(request.Password))
		{
			return BadRequest("Credentials Required");
		}

		// 1. Validate consuming application
		var isApplicationValid =
			await _applicationValidationService.ValidateApplicationAsync(
				request.ApplicationId,
				request.HashKey,
				cancellationToken);

		if (!isApplicationValid)
		{
			return Unauthorized("Invalid Application credentials");
		}

		// 2. Authenticate user
		var result = await _authenticationService.AuthenticateUserAsync(
			request.UserId,
			request.Password,
			cancellationToken);

		if (result == null)
		{
			return Unauthorized("Invalid User ID or Password");
		}

		// 3. Check user application access
		var isUserAllowed =
			await _userApplicationAccessService.IsUserAllowedAsync(
				result.UserId,
				request.ApplicationId,
				cancellationToken);

		if (!isUserAllowed)
		{
			return StatusCode(
				StatusCodes.Status403Forbidden,
				"You are not authorized to access this application");
		}

		// 4. Retrieve current roles and permissions
		var authorization =
			await _userAuthorizationProvider.GetCurrentAuthorizationAsync(
				result.UserId,
				request.ApplicationId,
				cancellationToken);

		if (authorization == null)
		{
			return StatusCode(
				StatusCodes.Status403Forbidden,
				"Employee authorization information unavailable");
		}

		// 5. Generate access and refresh tokens
		var tokens = await _tokenIssuanceService.IssueAsync(
			new TokenIssuanceRequest
			{
				PrincipalType = GlobalAuthPrincipalTypes.User,
				SubjectId = result.UserId,
				ApplicationId = request.ApplicationId,
				Roles = authorization.Roles,
				Permissions = authorization.Permissions,

				// Audit metadata
				IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString()
			},
			cancellationToken);

		// 6. Return login response

		return Ok(tokens);
	}
	[HttpPost("change-password")]
	[Authorize]
	public async Task<IActionResult> ChangePassword(
	[FromBody] ChangePasswordRequestDto request,
	CancellationToken cancellationToken)
	{
		// 1. Only USER principals can change passwords.
		var principalType =
			User.FindFirst(GlobalAuthClaimTypes.PrincipalType)?.Value;

		if (principalType != GlobalAuthPrincipalTypes.User)
			return Forbid();

		// 2. Extract identity and application context from JWT.
		var userId = User.FindFirst("sub")?.Value;

		var applicationId =
			User.FindFirst(GlobalAuthClaimTypes.ClientId)?.Value;

		var sessionIdValue =
			User.FindFirst(GlobalAuthClaimTypes.SessionId)?.Value;

		if (string.IsNullOrWhiteSpace(userId) ||
			string.IsNullOrWhiteSpace(applicationId) ||
			!Guid.TryParse(sessionIdValue, out var sessionId))
		{
			return Unauthorized();
		}

		// 3. Delegate password change to the service.
		var result = await _passwordChangeService.ChangePasswordAsync(
			userId,
			applicationId,
			sessionId,
			request.CurrentPassword,
			request.NewPassword,
			cancellationToken);

		// 4. Map service results to HTTP responses.
		switch (result)
		{
			case PasswordChangeResult.Success:
				return NoContent();

			case PasswordChangeResult.InvalidCurrentPassword:
				return BadRequest(new
				{
					message = "Current password is incorrect."
				});

			case PasswordChangeResult.SameAsCurrentPassword:
				return BadRequest(new
				{
					message = "New password must be different from the current password."
				});

			case PasswordChangeResult.UserUnavailable:
				return Forbid();

			case PasswordChangeResult.StateChanged:
				return Conflict(new
				{
					message = "Your account or session state has changed. Please sign in again."
				});

			default:
				return StatusCode(StatusCodes.Status500InternalServerError);
		}
	}
}