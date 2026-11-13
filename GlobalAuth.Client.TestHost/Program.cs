
using GlobalAuth.Client.DependencyInjection;
using GlobalAuth.Client.Authorization;

var builder = WebApplication.CreateBuilder(args);

// Register the GlobalAuth client library.
builder.Services.AddGlobalAuthentication(options =>
{
	options.Authority = "https://localhost:7226";
	options.Issuer = "https://localhost:7226";
	options.Audience = "GlobalAuthApis";
});

// Configure a permission-based authorization policy.
builder.Services.AddAuthorization(options =>
{
	options.AddPolicy("CanViewApplications", policy =>
	{
		policy.RequirePermission("application.view");
	});

	options.AddPolicy("CanDeleteApplications", policy =>
	{
		policy.RequirePermission("application.delete");
	});
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Requires a valid authenticated USER token.
app.MapGet("/profile", () =>
{
	return Results.Ok(new
	{
		message = "Authentication successful!"
	});
}).RequireAuthorization();

// Requires the application.view permission.
app.MapGet("/applications", () =>
{
	return Results.Ok(new
	{
		message = "You have permission to view applications."
	});
}).RequireAuthorization("CanViewApplications");

// Requires the application.delete permission.
app.MapGet("/applications/delete-test", () =>
{
	return Results.Ok(new
	{
		message = "You have permission to delete applications."
	});
}).RequireAuthorization("CanDeleteApplications");

app.Run();
