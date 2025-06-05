using Microsoft.AspNetCore.Identity;

namespace JWTAuthDotNetIdentity.Models.Entities
{
    public class ApplicationUser: IdentityUser
    {
        public string FullName { get; set; } = string.Empty;
        public string? RefreshToken { get; set; } = string.Empty;
        public DateTime? RefreshTokenExpirationDate { get; set; }
    }
}
