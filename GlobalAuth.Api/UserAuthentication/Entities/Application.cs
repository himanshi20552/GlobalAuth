namespace ApplicationAuthentication.Entities;

public class Application
{
	public string ApplicationID{get; set;} = string.Empty;
	public string HashKey { get; set;} = string.Empty;
	public bool IsActive { get; set;} 
}
