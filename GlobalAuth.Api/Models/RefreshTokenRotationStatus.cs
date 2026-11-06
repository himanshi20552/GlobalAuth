namespace GlobalAuth.Api.Models;

public enum RefreshTokenRotationStatus
{
	Rotated = 0,TokenNotFound = 1,TokenInvalid = 2,ReuseDetected = 3
}