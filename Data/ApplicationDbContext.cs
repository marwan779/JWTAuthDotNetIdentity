using JWTAuthDotNetIdentity.Models;
using JWTAuthDotNetIdentity.Models.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthDotNetIdentity.Data
{
    public class ApplicationDbContext: IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
            
        }

        public DbSet<ApplicationUser> ApplicationUsers { get; set; }
        public DbSet<ResetPasswordToken> ResetPasswordTokens { get; set; }
        public DbSet<RemoveAccountToken> RemoveAccountTokens { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
    }
}
