
using GlobalAuth.Api.Configuration;
using GlobalAuth.Api.Constants;
using GlobalAuth.Api.Contracts;
using GlobalAuth.Api.Models;
using GlobalAuth.Api.Repositories;
using Microsoft.Extensions.Options;

namespace GlobalAuth.Api.Services;

public sealed class TokenRefreshService
{
	private readonly AuthRefreshTokenRepository _userRefreshTokenRepository;
	private readonly ClientRefreshTokenRepository _clientRefreshTokenRepository;
	private readonly RefreshTokenService _refreshTokenService;
	private readonly ITokenService _tokenService;
	private readonly ClientPermissionRepository _clientPermissionRepository;
	private readonly IUserAuthorizationProvider? _userAuthorizationProvider;
	private readonly RefreshTokenOptions _refreshTokenOptions;
	private readonly SessionService _sessionService;

	public TokenRefreshService(
		AuthRefreshTokenRepository userRefreshTokenRepository,
		ClientRefreshTokenRepository clientRefreshTokenRepository,
		RefreshTokenService refreshTokenService,
		ITokenService tokenService,
		ClientPermissionRepository clientPermissionRepository,
		SessionService sessionService,
		IOptions<RefreshTokenOptions> refreshTokenOptions,
		IUserAuthorizationProvider? userAuthorizationProvider=null
		)
	{
		_userRefreshTokenRepository = userRefreshTokenRepository;
		_clientRefreshTokenRepository = clientRefreshTokenRepository;
		_refreshTokenService = refreshTokenService;
		_tokenService = tokenService;
		_clientPermissionRepository = clientPermissionRepository;
		_sessionService = sessionService;
		_userAuthorizationProvider = userAuthorizationProvider;
		_refreshTokenOptions = refreshTokenOptions.Value;

		if (_refreshTokenOptions.LifetimeDays <= 0)
			throw new InvalidOperationException(
				"Refresh token lifetime must be greater than zero.");
	}

	public async Task<RefreshTokenResponse> RefreshAsync(
		string presentedRefreshToken,
		string? ipAddress = null,
		CancellationToken cancellationToken = default)
	{
		if (string.IsNullOrWhiteSpace(presentedRefreshToken))
			throw new ArgumentException("Refresh token is required.");

		// Compute the hash once and use it for both lookups.
		var tokenHash = _refreshTokenService.ComputeHash(presentedRefreshToken);

		// First check whether this is a USER refresh token.
		var userContext =
			await _userRefreshTokenRepository.GetContextByTokenHashAsync(
				tokenHash, cancellationToken);

		if (userContext is not null)
		{
			return await RefreshUserTokenAsync(
				tokenHash, userContext, ipAddress, cancellationToken);
		}

		// If not found, check the CLIENT refresh-token table.
		var clientContext =
			await _clientRefreshTokenRepository.GetContextByTokenHashAsync(
				tokenHash, cancellationToken);

		if (clientContext is not null)
		{
			return await RefreshClientTokenAsync(
				tokenHash, clientContext, ipAddress, cancellationToken);
		}

		throw new UnauthorizedAccessException("Invalid refresh token.");
	}

	private async Task<RefreshTokenResponse> RefreshUserTokenAsync(
		byte[] presentedTokenHash,
		RefreshTokenContext context,
		string? ipAddress,
		CancellationToken cancellationToken)
	{
		var nowUtc = DateTime.UtcNow;

		// Do not reject used tokens here.
		// They must reach the stored procedure for reuse detection.
		if (!context.UsedAtUtc.HasValue)
		{
			if (context.RevokedAtUtc.HasValue ||
				context.TokenExpiresAtUtc <= nowUtc ||
				context.SessionRevokedAtUtc.HasValue ||
				context.SessionStatusID != 1 ||
				!context.ApplicationIsActive)
			{
				throw new UnauthorizedAccessException(
					"Refresh token or associated session is no longer active.");
			}
		}

		TokenResult? accessToken = null;

		if (!context.UsedAtUtc.HasValue)
		{
			if (_userAuthorizationProvider is null)
			{
				throw new InvalidOperationException(
					"User authorization provider is not configured.");
			}

			if (string.IsNullOrWhiteSpace(context.ApplicationID))
			{
				throw new InvalidOperationException(
					"User session has no ApplicationID.");
			}

			var authorization =
				await _userAuthorizationProvider.GetCurrentAuthorizationAsync(
					context.SubjectID,
					context.ApplicationID,
					cancellationToken);

			if (authorization is null)
			{
				await _sessionService.RevokeSessionAsync(
					context.SessionID,
					"TokenRefreshService.RefreshUserTokenAsync",
					cancellationToken);

				throw new UnauthorizedAccessException(
					"User is no longer authorized.");
			}

			var tokenRequest = new TokenGenerationRequest
			{
				PrincipalType = GlobalAuthPrincipalTypes.User,
				SubjectId = context.SubjectID,
				ApplicationId = context.ApplicationID,
				SessionId = context.SessionID,
				Roles = authorization.Roles,
				Permissions = authorization.Permissions
			};

			accessToken = _tokenService.GenerateAccessToken(tokenRequest);
		}

		var newRefreshToken = _refreshTokenService.Generate();
		var newRefreshTokenId = Guid.NewGuid();
		var newRefreshTokenExpiresAtUtc =
			nowUtc.AddDays(_refreshTokenOptions.LifetimeDays);

		// The stored procedure handles idle-timeout validation
		// and updates LastActivityAtUtc atomically.
		var resultCode =
			await _userRefreshTokenRepository.RotationAsync(
				presentedTokenHash,
				newRefreshTokenId,
				newRefreshToken.TokenHash,
				newRefreshTokenExpiresAtUtc,
				accessToken?.Jti,
				accessToken?.ExpiresAtUtc,
				ipAddress,
				cancellationToken);

		return resultCode switch
		{
			0 => new RefreshTokenResponse
			{
				AccessToken = accessToken!.AccessToken,
				RefreshToken = newRefreshToken.Token,
				ExpiresAtUtc = accessToken.ExpiresAtUtc
			},

			1 => throw new UnauthorizedAccessException(
				"Invalid refresh token."),

			2 => throw new UnauthorizedAccessException(
				"Refresh token or associated session is no longer valid."),

			3 => throw new UnauthorizedAccessException(
				"Refresh token reuse detected. The session has been revoked."),

			_ => throw new InvalidOperationException(
				"Unexpected user refresh-token rotation result.")
		};
	}

	private async Task<RefreshTokenResponse> RefreshClientTokenAsync(
		byte[] presentedTokenHash,
		ClientRefreshTokenContext context,
		string? ipAddress,
		CancellationToken cancellationToken)
	{
		var nowUtc = DateTime.UtcNow;

		// No client idle-timeout or session checks.
		// Used tokens must reach the procedure for reuse detection.
		if (!context.UsedAtUtc.HasValue)
		{
			if (context.RevokedAtUtc.HasValue ||
				context.TokenExpiresAtUtc <= nowUtc ||
				!context.ClientIsActive)
			{
				throw new UnauthorizedAccessException(
					"Client refresh token is expired or no longer active.");
			}
		}

		TokenResult? accessToken = null;

		if (!context.UsedAtUtc.HasValue)
		{
			var permissions =
				await _clientPermissionRepository
					.GetActivePermissionsByClientAsync(
						context.ClientID, cancellationToken);

			var tokenRequest = new TokenGenerationRequest
			{
				PrincipalType = GlobalAuthPrincipalTypes.Client,
				SubjectId = context.ClientID,
				Roles = [],
				Permissions = permissions.ToList()
			};

			accessToken = _tokenService.GenerateAccessToken(tokenRequest);
		}

		var newRefreshToken = _refreshTokenService.Generate();
		var newRefreshTokenId = Guid.NewGuid();
		var newRefreshTokenExpiresAtUtc =
			nowUtc.AddDays(_refreshTokenOptions.LifetimeDays);

		var resultCode =
			await _clientRefreshTokenRepository.RotateAsync(
				presentedTokenHash,
				newRefreshTokenId,
				newRefreshToken.TokenHash,
				newRefreshTokenExpiresAtUtc,
				accessToken?.Jti,
				accessToken?.ExpiresAtUtc,
				ipAddress,
				cancellationToken);

		return resultCode switch
		{
			0 => new RefreshTokenResponse
			{
				AccessToken = accessToken!.AccessToken,
				RefreshToken = newRefreshToken.Token,
				ExpiresAtUtc = accessToken.ExpiresAtUtc
			},

			1 => throw new UnauthorizedAccessException(
				"Invalid client refresh token."),

			2 => throw new UnauthorizedAccessException(
				"Client refresh token or client is no longer active."),

			3 => throw new UnauthorizedAccessException(
				"Client refresh token reuse detected. The token family has been revoked."),

			_ => throw new InvalidOperationException(
				"Unexpected client refresh-token rotation result.")
		};
	}

	// Logout applies only to USER sessions.
	// There is intentionally no client logout operation.
	public async Task LogoutAsync(
		string presentedRefreshToken,
		CancellationToken cancellationToken = default)
	{
		if (string.IsNullOrWhiteSpace(presentedRefreshToken))
			throw new ArgumentException("Refresh token is required.");

		var tokenHash = _refreshTokenService.ComputeHash(
			presentedRefreshToken);

		var context =
			await _userRefreshTokenRepository.GetContextByTokenHashAsync(
				tokenHash, cancellationToken);

		if (context is null)
		{
			throw new UnauthorizedAccessException(
				"Invalid user refresh token.");
		}

		await _sessionService.RevokeSessionAsync(
			context.SessionID,
			"TokenRefreshService.LogoutAsync",
			cancellationToken);
	}
}
