using EmployeePortalDemo.Services;
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpClient<AuthenticationApiClient>(client =>
{
	var baseUrl = builder.Configuration["AuthenticationApi:BaseUrl"]
		?? throw new InvalidOperationException("Authentication API Base URL is not configured.");
	client.BaseAddress = new Uri(baseUrl);
});

// Add services to the container.
builder.Services.AddRazorPages();

builder.Services.AddDistributedMemoryCache();

builder.Services.AddSession(options =>
{
	options.IdleTimeout = TimeSpan.FromMinutes(20);
	options.Cookie.HttpOnly = true;
	options.Cookie.IsEssential = true;
	options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseRouting();
app.UseSession();
app.UseAuthorization();

app.MapStaticAssets();
app.MapRazorPages()
   .WithStaticAssets();

app.Run();
