namespace ApplicationAuthentication.Entities
{
    public class Permission
    {
        public int PermissionID { get; set; }
        public string ApplicationId { get; set; } = string.Empty;
		public string PermissionCode { get; set; } = string.Empty;
        public string PermissionName { get; set; } = string.Empty ;
        public string? Description { get; set; }
        public bool IsActive { get; set; }
        public DateTime CreatedAt { get; set; }
    }
}
