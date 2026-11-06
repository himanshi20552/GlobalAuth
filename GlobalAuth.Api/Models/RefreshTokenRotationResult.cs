namespace GlobalAuth.Api.Models;

public sealed class RefreshTokenRotationResult
{
	public RefreshTokenRotationStatus ResultCode { get; set; }
	public Guid? SessionID { get; set; }
	public Guid? FamilyID { get; set; }
}