namespace ApplicationAuthentication.Entities;

public class Application
{
	public string ApplicationId{get; set;} = string.Empty;
	public string ApplicationName{get; set;} = string.Empty;
	public string HashKey { get; set;} = string.Empty;
	public bool IsActive { get; set;} 
	public DateTime CreatedAt { get; set;}
}
