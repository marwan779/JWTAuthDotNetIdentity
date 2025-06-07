namespace JWTAuthDotNetIdentity.Models.DTOs
{
    public class RemoveAccountDTO
    {
        public Guid TokenId { get; set; }

        public string Password { get; set; } = string.Empty;
    }
}
