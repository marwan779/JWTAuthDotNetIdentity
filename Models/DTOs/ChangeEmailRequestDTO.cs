namespace JWTAuthDotNetIdentity.Models.DTOs
{
    public class ChangeEmailRequestDTO
    {
        public string Password { get; set; } = string.Empty;
        public string NewEmail { get; set; } = string.Empty;
    }
}
