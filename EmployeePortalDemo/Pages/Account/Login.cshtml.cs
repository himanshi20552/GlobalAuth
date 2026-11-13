
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Http;
using EmployeePortalDemo.Services;
using EmployeePortalDemo.Models.Responses;
using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Text.Json;

namespace EmployeePortalDemo.Pages.Account
{
	public class LoginModel : PageModel
	{
		private readonly AuthenticationApiClient _authenticationApiClient;

		public LoginModel(AuthenticationApiClient authenticationApiClient)
		{
			_authenticationApiClient = authenticationApiClient;
		}

		[BindProperty]
		[Required(ErrorMessage = "Employee ID is required.")]
		public string UserId { get; set; } = string.Empty;

		[BindProperty]
		[Required(ErrorMessage = "Password is required.")]
		[DataType(DataType.Password)]
		public string Password { get; set; } = string.Empty;

		public LoginResponse? LoginResult { get; set; }

		public string? StatusMessage { get; set; }

		public void OnGet()
		{
		}

		public async Task<IActionResult> OnPostAsync()
		{
			// Step 1: Validate the submitted form
			if (!ModelState.IsValid)
			{
				return Page();
			}

			try
			{
				// Step 2: Call the existing Authentication API client
				LoginResult = await _authenticationApiClient.LoginAsync(
					UserId,
					Password,
					HttpContext.RequestAborted);

				// Step 3: Check whether the API returned a response
				if (LoginResult == null)
				{
					ModelState.AddModelError(
						string.Empty,
						"The authentication service returned an empty response.");

					return Page();
				}

				// Step 4: Convert the API response into JSON
				var loginData = JsonSerializer.Serialize(LoginResult);

				// Step 5: Store the response in server-side Session
				HttpContext.Session.SetString("EmployeeLogin", loginData);

				// Step 6: Redirect to the Dashboard
				return RedirectToPage("/Dashboard/Index");
			}
			catch (HttpRequestException ex)
			{
				// Step 7: Handle errors returned by the Authentication API
				var errorMessage = ex.StatusCode switch
				{
					HttpStatusCode.Unauthorized =>
						"Invalid login credentials.",

					HttpStatusCode.Forbidden =>
						"You don't have permission to access this resource.",

					HttpStatusCode.BadRequest =>
						"The login request was invalid.",

					_ =>
						"Unable to authenticate right now. Please try again later."
				};

				ModelState.AddModelError(string.Empty, errorMessage);

				return Page();
			}
		}
	}
}
