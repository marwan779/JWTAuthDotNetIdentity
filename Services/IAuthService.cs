using JWTAuthDotNetIdentity.Models;
using JWTAuthDotNetIdentity.Models.DTOs;
using JWTAuthDotNetIdentity.Models.Entities;

namespace JWTAuthDotNetIdentity.Services
{
    public interface IAuthService
    {
        Task<ApiResponse?> RegisterAsync(RegisterDTO registerDTO);
        Task<ApiResponse?> LoginAsync(LoginDTO loginDTO);
        Task<bool> LogoutAsync(string userId);
        Task<TokenResponseDTO?> RefreshTokensAsync(TokenRequestDTO tokenRequestDTO);
        Task<ApiResponse?> ChangePasswordAsync(string userId, ChangePasswordDTO changePasswordDTO);
        Task<ApiResponse?> GenerateResetPasswordTokenAsync(string Email);
        Task<ApiResponse?> ResetPasswordAsync(ResetPasswordDTO resetPasswordDTO);
        Task<TokenResponseDTO?> ExternalLoginAsync(ExternalLoginDTO loginDTO);


    }
}
