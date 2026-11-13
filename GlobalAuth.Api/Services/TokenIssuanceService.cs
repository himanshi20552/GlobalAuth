using GlobalAuth.Api.Configuration;
using GlobalAuth.Api.Constants;
using GlobalAuth.Api.Contracts;
using GlobalAuth.Api.Models;
using GlobalAuth.Api.Repositories;
using Microsoft.Extensions.Options;

namespace GlobalAuth.Api.Services;

public sealed class TokenIssuanceService : ITokenIssuanceService
{
	private readonly SessionService _sessionService;
	private readonly ITokenService _tokenService;
	private readonly RefreshTokenService _refreshTokenService;
	private readonly AuthRefreshTokenRepository _userRefreshTokenRepository;
	private readonly ClientRefreshTokenRepository _clientRefreshTokenRepository;
	private readonly RefreshTokenOptions _refreshTokenOptions;
	private readonly AuthTokenIssuanceAuditRepository _auditRepository;

	public TokenIssuanceService(
		SessionService sessionService,
		ITokenService tokenService,
		RefreshTokenService refreshTokenService,
		AuthRefreshTokenRepository userRefreshTokenRepository,
		ClientRefreshTokenRepository clientRefreshTokenRepository,
		IOptions<RefreshTokenOptions> refreshTokenOptions,
		AuthTokenIssuanceAuditRepository auditRepository)
	{
		_sessionService = sessionService;
		_tokenService = tokenService;
		_refreshTokenService = refreshTokenService;
		_userRefreshTokenRepository = userRefreshTokenRepository;
		_clientRefreshTokenRepository = clientRefreshTokenRepository;
		_refreshTokenOptions = refreshTokenOptions.Value;
		_auditRepository = auditRepository;

		if (_refreshTokenOptions.LifetimeDays <= 0)
		{
			throw new InvalidOperationException(
				"Refresh token lifetime must be greater than zero.");
		}
	}

	public async Task<RefreshTokenResponse> IssueAsync(
		TokenIssuanceRequest request,
		CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(request);
		ValidateRequest(request);

		return request.PrincipalType switch
		{
			GlobalAuthPrincipalTypes.User =>
				await IssueUserTokenAsync(request, cancellationToken),

			GlobalAuthPrincipalTypes.Client =>
				await IssueClientTokenAsync(request, cancellationToken),

			_ => throw new ArgumentException("Invalid principal type.")
		};
	}

	private async Task<RefreshTokenResponse> IssueUserTokenAsync(
		TokenIssuanceRequest request,
		CancellationToken cancellationToken)
	{
		// USER tokens require a database session.
		var sessionId = await _sessionService.CreateUserSessionAsync(
			request.SubjectId,
			request.ApplicationId!,
			request.VerifiedPasswordHash!,
			cancellationToken);

		try
		{
			var tokenRequest = new TokenGenerationRequest
			{
				PrincipalType = GlobalAuthPrincipalTypes.User,
				SubjectId = request.SubjectId,
				ApplicationId = request.ApplicationId,
				SessionId = sessionId,
				Roles = request.Roles,
				Permissions = request.Permissions
			};

			var accessToken = _tokenService.GenerateAccessToken(tokenRequest);
			var refreshToken = _refreshTokenService.Generate();

			var refreshTokenId = Guid.NewGuid();
			var familyId = Guid.NewGuid();
			var nowUtc = DateTime.UtcNow;
			var refreshTokenExpiresAtUtc =
				nowUtc.AddDays(_refreshTokenOptions.LifetimeDays);

			var stored = await _userRefreshTokenRepository.CreateAsync(
				refreshTokenId,
				sessionId,
				familyId,
				refreshToken.TokenHash,
				refreshTokenExpiresAtUtc,
				cancellationToken);

			if (!stored)
			{
				throw new InvalidOperationException(
					"User refresh token could not be stored. The session may no longer be active.");
			}

			await _auditRepository.CreateAsync(
				new AuthTokenIssuanceAudit
				{
					Jti = accessToken.Jti,
					PrincipalType = GlobalAuthPrincipalTypes.User,
					SubjectID = request.SubjectId,
					SessionID = sessionId,
					IssuanceType = "INITIAL",
					IssuedAtUtc = nowUtc,
					ExpiresAtUtc = accessToken.ExpiresAtUtc,
					IPAddress = request.IpAddress
				},
				cancellationToken);

			return new RefreshTokenResponse
			{
				AccessToken = accessToken.AccessToken,
				RefreshToken = refreshToken.Token,
				ExpiresAtUtc = accessToken.ExpiresAtUtc
			};
		}
		catch (Exception issuanceException)
		{
			try
			{
				await _sessionService.RevokeSessionAsync(
					sessionId,
					"TokenIssuanceService.IssueUserTokenAsync",
					CancellationToken.None);
			}
			catch (Exception cleanupException)
			{
				throw new AggregateException(
					"User token issuance failed and session cleanup also failed.",
					issuanceException,
					cleanupException);
			}

			throw;
		}
	}

	private async Task<RefreshTokenResponse> IssueClientTokenAsync(
		TokenIssuanceRequest request,
		CancellationToken cancellationToken)
	{
		// CLIENT tokens do not create sessions.
		var tokenRequest = new TokenGenerationRequest
		{
			PrincipalType = GlobalAuthPrincipalTypes.Client,
			SubjectId = request.SubjectId,
			Roles = [],
			Permissions = request.Permissions
		};

		var accessToken = _tokenService.GenerateAccessToken(tokenRequest);
		var refreshToken = _refreshTokenService.Generate();

		var clientRefreshTokenId = Guid.NewGuid();
		var familyId = Guid.NewGuid();
		var nowUtc = DateTime.UtcNow;
		var refreshTokenExpiresAtUtc =
			nowUtc.AddDays(_refreshTokenOptions.LifetimeDays);

		var stored = await _clientRefreshTokenRepository.CreateAsync(
			clientRefreshTokenId,
			request.SubjectId,
			familyId,
			refreshToken.TokenHash,
			refreshTokenExpiresAtUtc,
			cancellationToken);

		if (!stored)
		{
			throw new InvalidOperationException(
				"Client refresh token could not be stored. The client may be inactive.");
		}

		try
		{
			await _auditRepository.CreateAsync(
				new AuthTokenIssuanceAudit
				{
					Jti = accessToken.Jti,
					PrincipalType = GlobalAuthPrincipalTypes.Client,
					SubjectID = request.SubjectId,
					SessionID = null,
					IssuanceType = "INITIAL",
					IssuedAtUtc = nowUtc,
					ExpiresAtUtc = accessToken.ExpiresAtUtc,
					IPAddress = request.IpAddress
				},
				cancellationToken);
		}
		catch
		{
			// Do not leave an active refresh-token family behind
			// if initial issuance fails before the response is returned.
			await _clientRefreshTokenRepository.RevokeFamilyAsync(
				request.SubjectId,
				familyId,
				CancellationToken.None);

			throw;
		}

		return new RefreshTokenResponse
		{
			AccessToken = accessToken.AccessToken,
			RefreshToken = refreshToken.Token,
			ExpiresAtUtc = accessToken.ExpiresAtUtc
		};
	}

	private static void ValidateRequest(TokenIssuanceRequest request)
	{
		if (string.IsNullOrWhiteSpace(request.SubjectId))
			throw new ArgumentException("Subject ID is required.");

		if (request.Roles is null)
			throw new ArgumentException("Roles cannot be null.");

		if (request.Permissions is null)
			throw new ArgumentException("Permissions cannot be null.");

		var isUser =
			request.PrincipalType == GlobalAuthPrincipalTypes.User;

		var isClient =
			request.PrincipalType == GlobalAuthPrincipalTypes.Client;

		if (!isUser && !isClient)
			throw new ArgumentException("Invalid principal type.");

		if (isUser && string.IsNullOrWhiteSpace(request.ApplicationId))
			throw new ArgumentException("Application ID is required for user token issuance.");
		if (isUser && string.IsNullOrWhiteSpace(request.VerifiedPasswordHash))
			throw new ArgumentException("Verified password hash is required for user token issuance.");

		if (isClient && !string.IsNullOrWhiteSpace(request.ApplicationId))
            throw new ArgumentException("Application ID must not be supplied for client token issuance.");


		if (isClient && request.Roles.Count > 0)
			throw new ArgumentException("Client tokens cannot contain user roles.");
	}
}
