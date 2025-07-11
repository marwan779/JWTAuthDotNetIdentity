﻿using JWTAuthDotNetIdentity.Models;
using JWTAuthDotNetIdentity.Models.DTOs;
using JWTAuthDotNetIdentity.Models.Entities;

namespace JWTAuthDotNetIdentity.Services
{
    public interface IAuthService
    {
        Task<ApiResponse?> RegisterAsync(RegisterDTO registerDTO);
        Task<ApiResponse?> LoginAsync(LoginDTO loginDTO);
        Task<TokenResponseDTO?> RefreshTokensAsync(TokenRequestDTO tokenRequestDTO);
        Task<ApiResponse?> ChangePasswordAsync(string userId, ChangePasswordDTO changePasswordDTO);
        Task<ApiResponse?> GenerateChangeEmailTokenAsync(string userId, ChangeEmailRequestDTO changeEmailRequestDTO);
        Task<ApiResponse?> ConfirmEmailChangeAsync(string userId, ConfirmEmailChangeDTO confirmEmailChangeDTO);
        Task<ApiResponse?> GenerateResetPasswordTokenAsync(string Email);
        Task<ApiResponse?> ResetPasswordAsync(ResetPasswordDTO resetPasswordDTO);
        Task<TokenResponseDTO?> ExternalLoginAsync(ExternalLoginDTO loginDTO);
        Task<bool> RevokeRefreshTokenAsync(string refreshToken, string? ipAddress = null);
        Task<bool> RevokeAllUserRefreshTokensAsync(string userId, string? ipAddress = null);
        Task<ApiResponse?> GenerateRemoveAccountTokenAsync(string Email);
        Task<ApiResponse?> RemoveAccountAsync(RemoveAccountDTO removeAccountDTO, string userId);
        


    }
}
