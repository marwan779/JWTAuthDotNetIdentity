namespace JWTAuthDotNetIdentity.Models.DTOs
{
    public class TokenRequestDTO
    {
        public string UserId {  get; set; }  = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
    }
}
