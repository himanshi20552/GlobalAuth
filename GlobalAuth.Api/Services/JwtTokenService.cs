
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using GlobalAuth.Api.Configuration;
using GlobalAuth.Api.Constants;
using GlobalAuth.Api.Contracts;
using Microsoft.Extensions.Options;

namespace GlobalAuth.Api.Services;

public sealed class JwtTokenService : ITokenService
{
	private readonly ISigningKeyProvider _signingKeyProvider;
	private readonly JwtOptions _jwtOptions;

	public JwtTokenService(
		ISigningKeyProvider signingKeyProvider,
		IOptions<JwtOptions> options)
	{
		_signingKeyProvider = signingKeyProvider;
		_jwtOptions = options.Value;

		if (string.IsNullOrWhiteSpace(_jwtOptions.Issuer))
			throw new InvalidOperationException("JWT issuer is required.");

		if (string.IsNullOrWhiteSpace(_jwtOptions.Audience))
			throw new InvalidOperationException("JWT audience is required.");

		if (_jwtOptions.AccessTokenLifetimeMinutes <= 0)
			throw new InvalidOperationException(
				"Access token lifetime must be greater than zero.");
	}

	public TokenResult GenerateAccessToken(TokenGenerationRequest request)
	{
		ArgumentNullException.ThrowIfNull(request);

		if (string.IsNullOrWhiteSpace(request.SubjectId))
			throw new ArgumentException("Subject ID is required.");
		if (request.SessionId == Guid.Empty)
			throw new ArgumentException("Session ID is required.");
		if(request.Roles is null)
			throw new ArgumentException("Roles list cannot be null.");
		if(request.Permissions is null)
			throw new ArgumentException("Permissions list cannot be null.");
		var isUser=request.PrincipalType == GlobalAuthPrincipalTypes.User;
		var isClient = request.PrincipalType == GlobalAuthPrincipalTypes.Client;
		if(!isUser && !isClient)
			throw new ArgumentException("Invalid principal type.");
		if(isClient && request.Roles.Count > 0)
			throw new ArgumentException("Client tokens cannot contain user roles.");
		var now = DateTime.UtcNow;

		var expiresAt = now.AddMinutes(
			_jwtOptions.AccessTokenLifetimeMinutes);
		var jti=Guid.NewGuid().ToString();

		var claims = new List<Claim>
		{
			new(JwtRegisteredClaimNames.Sub, request.SubjectId),
			new(JwtRegisteredClaimNames.Jti, jti),
			new(JwtRegisteredClaimNames.Iat,new DateTimeOffset(now).ToUnixTimeSeconds().ToString(),ClaimValueTypes.Integer64),
			new(GlobalAuthClaimTypes.PrincipalType, request.PrincipalType),
			new(GlobalAuthClaimTypes.SessionId, request.SessionId.ToString()),
			new(GlobalAuthClaimTypes.TokenType, "access")

		};
		var clientId = request.PrincipalType switch
		{
			GlobalAuthPrincipalTypes.User => request.ApplicationId?? throw new ArgumentException(
			"Application ID is required for user tokens."),
			GlobalAuthPrincipalTypes.Client => request.SubjectId,
			_ => throw new InvalidOperationException("Invalid principal type.")
		};

		claims.Add(new Claim(GlobalAuthClaimTypes.ClientId, clientId));
		if (isUser)
		{ 
			foreach (var role in request.Roles.Distinct())
			{
				if (!string.IsNullOrWhiteSpace(role))
				{
					claims.Add(new Claim(GlobalAuthClaimTypes.Role, role));
				}
			}
		}

		foreach (var permission in request.Permissions.Distinct())
		{
			if (!string.IsNullOrWhiteSpace(permission))
			{
				claims.Add(new Claim(
					GlobalAuthClaimTypes.Permission,
					permission));
			}
		}

		var token = new JwtSecurityToken(
			issuer: _jwtOptions.Issuer,
			audience: _jwtOptions.Audience,
			claims: claims,
			notBefore: now,
			expires: expiresAt,
			signingCredentials:_signingKeyProvider.GetSigningCredentials()
		);
		token.Header["typ"] = "at+jwt";
		var tokenHandler = new JwtSecurityTokenHandler();
		return new TokenResult
		{
			AccessToken = tokenHandler.WriteToken(token),
			Jti=jti,
			ExpiresAtUtc = expiresAt
		};
	}
}
