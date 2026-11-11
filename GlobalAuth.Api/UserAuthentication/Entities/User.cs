using Microsoft.AspNetCore.Identity;
namespace ApplicationAuthentication.Entities
{
    public class User
    {
        public string UserId { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public bool IsActive { get; set; }
        public bool IsBlocked { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}
