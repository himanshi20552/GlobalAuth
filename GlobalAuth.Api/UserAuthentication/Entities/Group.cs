namespace ApplicationAuthentication.Entities
{
    public class Group
    {
        public int GroupId { get; set; }
        public string ApplicationId { get; set; } = string.Empty;
		public string GroupName { get; set; } = string.Empty;
        public bool IsActive { get; set; }
        public DateTime CreatedAt { get; set; }

    }
}
