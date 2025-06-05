using JWTAuthDotNetIdentity.Models;
using JWTAuthDotNetIdentity.Models.DTOs;
using JWTAuthDotNetIdentity.Models.Entities;

namespace JWTAuthDotNetIdentity.Services
{
    public interface IAuthService
    {
        Task<ApiResponse?> RegisterAsync(RegisterDTO registerDTO);

        Task<ApiResponse?> LoginAsync(LoginDTO loginDTO);

        Task<TokenResponseDTO?> RefreshTokens(TokenRequestDTO tokenRequestDTO);
    }
}
