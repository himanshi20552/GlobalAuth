using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using GlobalAuth.Api.Configuration;
using GlobalAuth.Api.Contracts;
using GlobalAuth.Api.Models;
using GlobalAuth.Api.Repositories;
using Microsoft.Extensions.Options;
namespace GlobalAuth.Api.Services
{
	public sealed class TokenRefreshService
	{
		private readonly AuthRefreshTokenRepository _refreshTokenRepository;
		private readonly RefreshTokenService _refreshTokenService;
		private readonly ITokenService _tokenService;
		private readonly ClientPermissionRepository _clientPermissionRepository;
		private readonly IUserAuthorizationProvider _userAuthorizationProvider;
		private readonly RefreshTokenOptions _refreshTokenOptions;
		private readonly SessionService _sessionService;
		public TokenRefreshService(AuthRefreshTokenRepository refreshTokenRepository, RefreshTokenService refreshTokenService, ITokenService tokenService,
	 ClientPermissionRepository clientPermissionRepository, SessionService sessionService,
	 IUserAuthorizationProvider userAuthorizationProvider, IOptions<RefreshTokenOptions> refreshTokenOptions)
		{
			_refreshTokenRepository = refreshTokenRepository;
			_refreshTokenService = refreshTokenService;
			_tokenService = tokenService;
			_clientPermissionRepository = clientPermissionRepository;
			_userAuthorizationProvider = userAuthorizationProvider;
			_refreshTokenOptions = refreshTokenOptions.Value;
			_sessionService = sessionService;
		}
		public async Task<RefreshTokenContext?> GetRefreshContextAsync(string presentedRefreshToken, CancellationToken cancellationToken = default)
		{
			if (string.IsNullOrWhiteSpace(presentedRefreshToken))
				return null;
			var tokenHash = _refreshTokenService.ComputeHash(presentedRefreshToken);
			return await _refreshTokenRepository.GetContextByTokenHashAsync(tokenHash, cancellationToken);
		}
		private async Task<UserAuthorizationResult?> GetAuthorizationAsync(RefreshTokenContext context, CancellationToken cancellationToken)
		{
			if (context.SubjectType == "USER")
			{
				if (string.IsNullOrWhiteSpace(context.ApplicationID))
					throw new InvalidOperationException("User session has no ApplicationID.");

				return await _userAuthorizationProvider.GetCurrentAuthorizationAsync(
					context.SubjectID,
					context.ApplicationID,
					cancellationToken);
			}

			if (context.SubjectType == "CLIENT")
			{
				var permissions =
					await _clientPermissionRepository.GetActivePermissionsByClientAsync(
						context.SubjectID,
						cancellationToken);

				return new UserAuthorizationResult
				{
					Permissions = permissions.ToList()
				};
			}

			throw new InvalidOperationException("Invalid session principal type.");
		}
		public async Task<RefreshTokenResponse> RefreshAsync(string presentedRefreshToken, CancellationToken cancellationToken = default)
		{
			if (string.IsNullOrWhiteSpace(presentedRefreshToken))
				throw new ArgumentException("Refresh token is required.");

			var context = await GetRefreshContextAsync(presentedRefreshToken, cancellationToken);

			if (context is null)
				throw new UnauthorizedAccessException("Invalid refresh token.");

			var nowUtc = DateTime.UtcNow;

			if (!context.UsedAtUtc.HasValue)
			{
				if (context.TokenExpiresAtUtc <= nowUtc || context.SessionRevokedAtUtc.HasValue || context.SessionExpiresAtUtc <= nowUtc)
				{
					throw new UnauthorizedAccessException("Refresh token or session has expired or is no longer active.");
				}
			}
			UserAuthorizationResult? authorization = null;

			// Previously used tokens must reach the rotation procedure
			// so that reuse detection is not bypassed.
			if (!context.UsedAtUtc.HasValue)
			{
				authorization = await GetAuthorizationAsync(context, cancellationToken);
				if (authorization is null)
				{
					await _sessionService.RevokeSessionAsync(context.SessionID,
					"User no longer authorized", cancellationToken);
					throw new UnauthorizedAccessException("User is no longer authorized.");
				}
			}
			var newRefreshToken = _refreshTokenService.Generate();
			var newRefreshTokenId = Guid.NewGuid();
			var newRefreshTokenExpiresAtUtc = nowUtc.AddDays(_refreshTokenOptions.LifetimeDays);
			if (newRefreshTokenExpiresAtUtc > context.SessionExpiresAtUtc)
			{ newRefreshTokenExpiresAtUtc = context.SessionExpiresAtUtc; }

			TokenResult? accessToken = null;
			if (!context.UsedAtUtc.HasValue)
			{
				var tokenRequest = new TokenGenerationRequest
				{
					PrincipalType = context.SubjectType,
					SubjectId = context.SubjectID,
					ApplicationId = context.ApplicationID,
					SessionId = context.SessionID,
					Roles = authorization!.Roles,
					Permissions = authorization.Permissions,
					SessionExpiresAtUtc=context.SessionExpiresAtUtc
				};
				accessToken = _tokenService.GenerateAccessToken(tokenRequest);
			}
			var presentedTokenHash = _refreshTokenService.ComputeHash(presentedRefreshToken);
			var rotationResult = await _refreshTokenRepository.RotationAsync(presentedTokenHash,
				newRefreshTokenId, newRefreshToken.TokenHash, newRefreshTokenExpiresAtUtc, cancellationToken);

			switch (rotationResult.ResultCode)
			{
				case RefreshTokenRotationStatus.Rotated:
					return new RefreshTokenResponse
					{
						AccessToken = accessToken!.AccessToken,
						RefreshToken = newRefreshToken.Token,
						ExpiresAtUtc = accessToken.ExpiresAtUtc
					};
				case RefreshTokenRotationStatus.ReuseDetected:
					throw new UnauthorizedAccessException("Refresh token reuse detected. The session has been revoked.");
				case RefreshTokenRotationStatus.TokenNotFound:
					throw new UnauthorizedAccessException("Invalid refresh token.");
				case RefreshTokenRotationStatus.TokenInvalid:
					throw new UnauthorizedAccessException(
						"Refresh token or associated session is no longer valid.");

				default: throw new InvalidOperationException("Unexpected refresh token rotation result.");
			}
		}
	}
}
