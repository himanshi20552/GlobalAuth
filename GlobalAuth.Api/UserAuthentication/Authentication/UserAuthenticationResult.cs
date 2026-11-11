using ApplicationAuthentication.Entities;
namespace ApplicationAuthentication.Authentication;

public class UserAuthenticationResult
{
	public string UserId { get; set; } = string.Empty;
	public string UserName { get; set; }= string.Empty;
	//public IEnumerable<Group> Groups {get; set;} = Enumerable.Empty<Group>();
	//public IEnumerable<Permission> Permissions { get; set; } = Enumerable.Empty<Permission>();
}
