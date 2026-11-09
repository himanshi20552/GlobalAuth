using GlobalAuth.Api.Configuration;
using GlobalAuth.Api.Repositories;
using GlobalAuth.Api.Models;
using GlobalAuth.Api.Contracts;

using Microsoft.Extensions.Options;
using GlobalAuth.Api.Constants;

namespace GlobalAuth.Api.Services
{
    public sealed class TokenIssuanceService:ITokenIssuanceService
    {
		private readonly SessionService _sessionService;
		private readonly ITokenService _tokenService;
		private readonly RefreshTokenService _refreshTokenService;
		private readonly AuthRefreshTokenRepository _refreshTokenRepository;
		private readonly RefreshTokenOptions _refreshTokenOptions;
		private readonly AuthTokenIssuanceAuditRepository _auditRepo;
		public TokenIssuanceService(SessionService sessionService, ITokenService tokenService,
		RefreshTokenService refreshTokenService, AuthRefreshTokenRepository refreshTokenRepository,
		IOptions<RefreshTokenOptions> refreshTokenOptions, AuthTokenIssuanceAuditRepository auditRepo)
		{
			_sessionService = sessionService;
			_tokenService = tokenService;
			_refreshTokenService = refreshTokenService;
			_refreshTokenRepository = refreshTokenRepository;
			_refreshTokenOptions = refreshTokenOptions.Value;
			if (_refreshTokenOptions.LifetimeDays <= 0)
				throw new InvalidOperationException("Token Lifetime must be greater than 0");
			_auditRepo = auditRepo;
		}
		public async Task<RefreshTokenResponse> IssueAsync(TokenIssuanceRequest request, CancellationToken cancellationToken = default)
		{
			ArgumentNullException.ThrowIfNull(request);
			ValidateRequest(request);
			var nowUtc = DateTime.UtcNow;
			var sessionExpiresAtUtc = nowUtc.AddDays(_refreshTokenOptions.LifetimeDays);
			var sessionRequest = new SessionCreationRequest
			{
				SubjectId = request.SubjectId,
				ApplicationId = request.ApplicationId,
				DeviceId = request.DeviceId,
				IpAddress = request.IpAddress,
				UserAgent = request.UserAgent,
				ExpiresAtUtc = sessionExpiresAtUtc
			};
			Guid sessionId = request.PrincipalType switch
			{
				GlobalAuthPrincipalTypes.User => await _sessionService.CreateUserSessionAsync(sessionRequest,
			cancellationToken),
				GlobalAuthPrincipalTypes.Client => await _sessionService.CreateClientSessionAsync(sessionRequest,
				cancellationToken),
				_ => throw new InvalidOperationException("Invalid Principal type")
			};
			try
			{
				var tokenRequest = new TokenGenerationRequest
				{
					PrincipalType = request.PrincipalType,
					SubjectId = request.SubjectId,
					ApplicationId = request.ApplicationId,
					Roles = request.Roles,
					Permissions = request.Permissions,
					SessionId = sessionId,
					SessionExpiresAtUtc=sessionExpiresAtUtc
				};
				var accessToken = _tokenService.GenerateAccessToken(tokenRequest);
				var refreshToken = _refreshTokenService.Generate();
				var refreshTokenId = Guid.NewGuid();
				var familyId = Guid.NewGuid();
				var refreshTokenExpiresAtUtc = sessionExpiresAtUtc;
				var stored = await _refreshTokenRepository.CreateAsync(refreshTokenId, sessionId,
					familyId, refreshToken.TokenHash, refreshTokenExpiresAtUtc, cancellationToken);
				if (!stored)
					throw new InvalidOperationException("Refresh Token couldnt be stored. Session may no longer be active");
				await _auditRepo.CreateAsync(new AuthTokenIssuanceAudit
				{
					Jti = accessToken.Jti,
					SessionID = sessionId,
					IssuanceType = "INITIAL",
					IssuedAtUtc = DateTime.UtcNow,
					ExpiresAtUtc = accessToken.ExpiresAtUtc,
					IPAddress = request.IpAddress,
					UserAgent = request.UserAgent,
					DeviceID = request.DeviceId
				}, cancellationToken);
				return new RefreshTokenResponse
				{
					AccessToken = accessToken.AccessToken,
					RefreshToken = refreshToken.Token,
					ExpiresAtUtc = accessToken.ExpiresAtUtc
				};

			}
			catch (Exception issuanceException) {
				try
				{
					await _sessionService.RevokeSessionAsync(sessionId, "token issuance failed", CancellationToken.None);

				}
				catch (Exception cleanupException) {
					throw new AggregateException("Token issuance failed and session cleanup also failed.",
					issuanceException,cleanupException);

				}
				throw;

			}

		}
		private static void ValidateRequest(TokenIssuanceRequest request) {
			if (string.IsNullOrWhiteSpace(request.SubjectId))
				throw new ArgumentException("Subject ID is required.");
	
			if (request.Roles is null)
				throw new ArgumentException("Roles cannot be null.");

			if (request.Permissions is null)
				throw new ArgumentException("Permissions cannot be null.");

			var isUser =request.PrincipalType == GlobalAuthPrincipalTypes.User;

			var isClient =request.PrincipalType == GlobalAuthPrincipalTypes.Client;

			if (!isUser && !isClient)
				throw new ArgumentException("Invalid principal type.");

			if (isUser && string.IsNullOrWhiteSpace(request.ApplicationId))
				throw new ArgumentException(
					"Application ID is required for user token issuance.");

			if (isClient && !string.IsNullOrWhiteSpace(request.ApplicationId))
				throw new ArgumentException(
					"Application ID must not be supplied for client token issuance.");

			if (isClient && request.Roles.Count > 0)
				throw new ArgumentException(
					"Client tokens cannot contain user roles.");

		}
	}
}
