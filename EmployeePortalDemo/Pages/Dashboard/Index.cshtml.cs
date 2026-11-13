
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using EmployeePortalDemo.Models.Responses;
using System.Text.Json;

namespace EmployeePortalDemo.Pages.Dashboard
{
	public class IndexModel : PageModel
	{
		public LoginResponse? Employee { get; private set; }

		public IActionResult OnGet()
		{
			// Retrieve the login response from Session
			var loginData = HttpContext.Session.GetString("EmployeeLogin");

			// Redirect to Login if no session exists
			if (string.IsNullOrEmpty(loginData))
			{
				return RedirectToPage("/Account/Login");
			}

			try
			{
				// Deserialize the stored login response
				Employee = JsonSerializer.Deserialize<LoginResponse>(loginData);

				// Validate the deserialized response
				if (Employee == null ||
					string.IsNullOrEmpty(Employee.AccessToken) ||
					string.IsNullOrEmpty(Employee.RefreshToken))
				{
					HttpContext.Session.Clear();
					return RedirectToPage("/Account/Login");
				}

				return Page();
			}
			catch (JsonException)
			{
				HttpContext.Session.Clear();
				return RedirectToPage("/Account/Login");
			}
		}
	}
}
