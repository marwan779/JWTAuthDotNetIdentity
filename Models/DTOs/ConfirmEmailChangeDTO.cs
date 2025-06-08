namespace JWTAuthDotNetIdentity.Models.DTOs
{
    public class ConfirmEmailChangeDTO
    {
        public string NewEmail { get; set; } = string.Empty;
        public Guid Token { get; set; }
    }
}
