using System.ComponentModel.DataAnnotations;

namespace JWTAuthDotNetIdentity.Models.DTOs
{
    public class LoginDTO
    {
        [Required]
        public string UserName { get; set; } = string.Empty;
        
        [Required]
        public string Password { get; set; } = string.Empty;
    }
}
