using GlobalAuth.Api.Configuration;
using GlobalAuth.Api.Services;
using GlobalAuth.Api.Data;
using GlobalAuth.Api.Repositories;
var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();
builder.Services.AddSingleton<SqlConnectionFactory>();
builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("Jwt"));
builder.Services.Configure<RefreshTokenOptions>(builder.Configuration.GetSection("RefreshToken"));
builder.Services.AddScoped<ITokenService, JwtTokenService>();
builder.Services.AddScoped<SessionService>();
builder.Services.AddScoped<ClientCredentialRepository>();
builder.Services.AddScoped<TokenRefreshService>();
builder.Services.AddSingleton<RefreshTokenService>();
builder.Services.AddScoped<AuthTokenIssuanceAuditRepository>();
builder.Services.AddScoped<ITokenIssuanceService, TokenIssuanceService>();
builder.Services.AddScoped<ClientAuthenticationService>();
builder.Services.AddScoped<ClientPermissionRepository>();
builder.Services.AddScoped<AuthRefreshTokenRepository>();
builder.Services.AddSingleton<ISigningKeyProvider, RsaFileSigningKeyProvider>();
builder.Services.AddScoped<AuthSessionRepository>();
var app = builder.Build();
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
