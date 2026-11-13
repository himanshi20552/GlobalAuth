
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
			// Step 1: Retrieve the login response from Session
			var loginData = HttpContext.Session.GetString("EmployeeLogin");

			// Step 2: If no login data exists, return to Login
			if (string.IsNullOrEmpty(loginData))
			{
				return RedirectToPage("/Account/Login");
			}

			try
			{
				// Step 3: Convert JSON back into LoginResponse
				Employee = JsonSerializer.Deserialize<LoginResponse>(loginData);

				// Step 4: Check whether the response was valid
				if (Employee == null)
				{
					HttpContext.Session.Clear();
					return RedirectToPage("/Account/Login");
				}

				// Step 5: Display the Dashboard
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
