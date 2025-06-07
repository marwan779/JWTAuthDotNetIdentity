namespace JWTAuthDotNetIdentity.Models.DTOs
{
    public class ChangeEmailDTO
    {
        public string CurrentEmail { get; set; } = string.Empty;
        public string NewEmail { get; set; } = string.Empty;
    }
}
