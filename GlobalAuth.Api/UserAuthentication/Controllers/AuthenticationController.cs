using ApplicationAuthentication.Authentication.Interfaces;
using ApplicationAuthentication.DTOs.Requests;
using ApplicationAuthentication.DTOs.Responses;
using Microsoft.AspNetCore.Mvc;
using ApplicationAuthentication.Services.Interfaces;

namespace ApplicationAuthentication.Controllers;

[ApiController] //controller declaration
[Route("api/[controller]")] //  /api/Authentication
public class AuthenticationController : ControllerBase
{
	private readonly IAuthenticationService _authenticationService;
	private readonly IApplicationValidationService _applicationValidationService;
	private readonly IUserAuthorizationProvider _userAuthorizationProvider;
	private readonly IUserApplicationAccessService _userApplicationAccessService;
	public AuthenticationController(IAuthenticationService authenticationService,
		IApplicationValidationService applicationValidationService,
		IUserAuthorizationProvider userAuthorizationProvider,
		IUserApplicationAccessService userApplicationAccessService
		)
	{
		_authenticationService = authenticationService;
		_applicationValidationService = applicationValidationService;
		_userAuthorizationProvider = userAuthorizationProvider;
		_userApplicationAccessService = userApplicationAccessService;
	}
	[HttpPost("login")] //HTTP POST endpoint ( POST/api/Authentication/login)
	public async Task<IActionResult> Login([FromBody] LoginRequestDto request, CancellationToken cancellationToken) { //request body 
		if (string.IsNullOrWhiteSpace(request.ApplicationId) || string.IsNullOrWhiteSpace(request.HashKey) ||
			string.IsNullOrWhiteSpace(request.UserId) || string.IsNullOrWhiteSpace(request.Password))
		{
			return BadRequest("Credentials Rquired");
		}
		var isApplicationValid = await _applicationValidationService.ValidateApplicationAsync(request.ApplicationId, request.HashKey);
		if (!isApplicationValid)
		{
			return Unauthorized("Invalid Application credentials");
		}
		//calling the authentication service
		var result = await _authenticationService.AuthenticateUserAsync(request.UserId, request.Password);
		if (result == null) {
			return Unauthorized("Invalid User ID or Passowrd");
		}
		var isUserAllowed = await _userApplicationAccessService.IsUserAllowedAsync(result.UserId, request.ApplicationId);
		if (!isUserAllowed)
		{
			return StatusCode(StatusCodes.Status403Forbidden, "You are not authorized to access this");
		}
		var authorization = await _userAuthorizationProvider.GetCurrentAuthorizationAsync(result.UserId, request.ApplicationId, cancellationToken);
		if (authorization == null)
		{
			return StatusCode(StatusCodes.Status403Forbidden, "Employee authorization info Unavailable");
		}
		var response = new LoginResponseDto
		{
            UserId = result.UserId, // returns collection of group and permission entities
            UserName = result.UserName,
			Groups = authorization.Roles,
			Permissions = authorization.Permissions
		};
		return Ok(response);
	}
}
