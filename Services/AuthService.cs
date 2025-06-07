using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JWTAuthDotNetIdentity.Data;
using JWTAuthDotNetIdentity.Models;
using JWTAuthDotNetIdentity.Models.DTOs;
using JWTAuthDotNetIdentity.Models.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Security.Cryptography;

namespace JWTAuthDotNetIdentity.Services
{
    public class AuthService : IAuthService
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _config;
        private readonly IHttpContextAccessor _httpContextAccessor;
        public AuthService(ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            IConfiguration config,
            IHttpContextAccessor httpContextAccessor)
        {
            _context = context;
            _userManager = userManager;
            _config = config;
            _httpContextAccessor = httpContextAccessor;
        }

        public async Task<ApiResponse?> LoginAsync(LoginDTO loginDTO)
        {
            if (loginDTO == null)
                return null;

            ApplicationUser? applicationUser = await _context.ApplicationUsers
                .FirstOrDefaultAsync(u => u.UserName == loginDTO.UserName);

            if (applicationUser == null)
                return new ApiResponse()
                {
                    ErrorMessage = $"no such user {loginDTO.UserName} !",
                    Result = null,
                    IsSuccess = false,
                    StatusCode = HttpStatusCode.NotFound
                };

            bool passwordValid = await _userManager.CheckPasswordAsync(applicationUser, loginDTO.Password);

            if (!passwordValid)
                return new ApiResponse()
                {
                    ErrorMessage = "Wrong password !",
                    Result = null,
                    IsSuccess = false,
                    StatusCode = HttpStatusCode.BadRequest
                };

            TokenResponseDTO tokenResponseDTO = new TokenResponseDTO()
            {
                AccessToken = await GenerateAccessToken(applicationUser),
                RefreshToken = await SaveRefreshTokenAsync(applicationUser),
                AccessTokenExpires = DateTime.UtcNow.AddMinutes(30),
                RefreshTokenExpires = DateTime.UtcNow.AddDays(7)
            };


            return new ApiResponse()
            {
                ErrorMessage = "",
                Result = tokenResponseDTO,
                IsSuccess = true,
                StatusCode = HttpStatusCode.OK
            };
        }

        public async Task<ApiResponse?> RegisterAsync(RegisterDTO registerDTO)
        {

            if (registerDTO == null)
            {
                return null;
            }
            else
            {
                var existingEmailUser = await _userManager.FindByEmailAsync(registerDTO.Email);

                if (!UserNameUnique(registerDTO.UserName))
                {
                    return new ApiResponse()
                    {
                        ErrorMessage = $"a user with the same username {registerDTO.UserName} already exists !, try onther one",
                        Result = null,
                        IsSuccess = false,
                        StatusCode = HttpStatusCode.Conflict
                    };
                }
                else if (existingEmailUser != null)
                {
                    return new ApiResponse()
                    {
                        ErrorMessage = $"A user with the email '{registerDTO.Email}' already exists!",
                        Result = null,
                        IsSuccess = false,
                        StatusCode = HttpStatusCode.Conflict
                    };
                }
                else
                {
                    ApplicationUser applicationUser = new ApplicationUser()
                    {
                        FullName = registerDTO.FullName,
                        UserName = registerDTO.UserName.ToLower(),
                        Email = registerDTO.Email,
                        PhoneNumber = registerDTO.PhoneNumber
                    };

                    IdentityResult? result = await _userManager.CreateAsync(applicationUser, registerDTO.Password);

                    if (result.Succeeded)
                    {

                        if (registerDTO.Email.Contains("admin"))
                        {
                            await _userManager.AddToRoleAsync(applicationUser, "Admin");
                        }
                        else
                        {
                            await _userManager.AddToRoleAsync(applicationUser, "User");
                        }


                        ApplicationUserDTO applicationUserDTO = new ApplicationUserDTO()
                        {
                            FullName = applicationUser.FullName,
                            UserName = applicationUser.UserName,
                            Email = applicationUser.Email,
                            PhoneNumber = applicationUser.PhoneNumber,
                        };


                        return new ApiResponse()
                        {
                            ErrorMessage = "",
                            Result = applicationUserDTO,
                            IsSuccess = true,
                            StatusCode = HttpStatusCode.Created
                        }; ;
                    }
                    else
                    {
                        return new ApiResponse()
                        {
                            ErrorMessage = "The password must consist of at least 6 characters, including uppercase, lowercase, a digit, and a special character.",
                            Result = null,
                            IsSuccess = false,
                            StatusCode = HttpStatusCode.BadRequest
                        };
                    }
                }
            }


        }

        public async Task<TokenResponseDTO?> RefreshTokensAsync(TokenRequestDTO tokenRequestDTO)
        {
            RefreshToken? refreshToken = await _context.RefreshTokens
                .Include(r => r.User)
                .FirstOrDefaultAsync(r => r.Token == tokenRequestDTO.RefreshToken);

            bool result = !await ValidateRefreshToken(refreshToken);
            if (result) return null;

            string ipAddress = GetClientIpAddress();

            refreshToken.RevokedAt = DateTime.Now;
            refreshToken.RevokedByIp = ipAddress;

            string newRefreshToken = await SaveRefreshTokenAsync(refreshToken.User, ipAddress);

            refreshToken.ReplacedByToken = newRefreshToken;

            await _context.SaveChangesAsync();

            return new TokenResponseDTO()
            {
                AccessToken = await GenerateAccessToken(refreshToken.User),
                RefreshToken = newRefreshToken,
                AccessTokenExpires = DateTime.Now.AddMinutes(30),
                RefreshTokenExpires = DateTime.Now.AddDays(7),
            };
        }

        public async Task<ApiResponse?> ChangePasswordAsync(string userId, ChangePasswordDTO changePasswordDTO)
        {
            ApplicationUser? applicationUser = await _context.ApplicationUsers
                .FirstOrDefaultAsync(u => u.Id == userId);

            if (applicationUser == null)
            {
                return new ApiResponse()
                {
                    IsSuccess = false,
                    StatusCode = HttpStatusCode.NotFound,
                    ErrorMessage = "No such user !",
                    Result = null,
                };
            }

            var result = await _userManager
                .ChangePasswordAsync(applicationUser, changePasswordDTO.CurrentPassword, changePasswordDTO.NewPassword);

            if (!result.Succeeded)
            {
                var errorDescription = string.Join("; ", result.Errors.Select(e => e.Description));

                return new ApiResponse()
                {
                    IsSuccess = false,
                    StatusCode = HttpStatusCode.BadRequest,
                    ErrorMessage = errorDescription,
                    Result = null,
                };
            }

            return new ApiResponse()
            {
                IsSuccess = true,
                StatusCode = HttpStatusCode.OK,
            };


        }

        public async Task<ApiResponse?> GenerateResetPasswordTokenAsync(string Email)
        {
            ApplicationUser? applicationUser = await _userManager.FindByEmailAsync(Email);

            if (applicationUser == null)
            {
                return new ApiResponse()
                {
                    IsSuccess = false,
                    StatusCode = HttpStatusCode.NotFound,
                    ErrorMessage = "No user with this email found",
                    Result = null,
                };
            }

            ResetPasswordToken resetPasswordToken = new ResetPasswordToken()
            {
                UserId = applicationUser.Id,
                ExpiresAt = DateTime.Now.AddMinutes(15),
                Token = await _userManager.GeneratePasswordResetTokenAsync(applicationUser),
                ApplicationUser = applicationUser
            };

            _context.ResetPasswordTokens.Add(resetPasswordToken);
            await _context.SaveChangesAsync();

            return new ApiResponse()
            {
                IsSuccess = true,
                StatusCode = HttpStatusCode.OK,
                Result = resetPasswordToken,
            };
        }

        public async Task<ApiResponse?> ResetPasswordAsync(ResetPasswordDTO resetPasswordDTO)
        {
            ResetPasswordToken? resetPasswordToken =
                await _context.ResetPasswordTokens.FirstOrDefaultAsync(t => t.Id == resetPasswordDTO.TokenId);

            if (resetPasswordToken == null || resetPasswordToken.IsUsed == true)
                return new ApiResponse()
                {
                    IsSuccess = false,
                    StatusCode = HttpStatusCode.NotFound,
                    ErrorMessage = "Invaild Token !",
                    Result = null,
                };

            if (resetPasswordToken.ExpiresAt <= DateTime.Now)
                return new ApiResponse()
                {
                    IsSuccess = false,
                    StatusCode = HttpStatusCode.NotFound,
                    ErrorMessage = "Expired Token !",
                    Result = null,
                };

            ApplicationUser? applicationUser = await _context.ApplicationUsers
                .FirstOrDefaultAsync(a => a.Id == resetPasswordToken.UserId);

            var result = await _userManager
                .ResetPasswordAsync(applicationUser, resetPasswordToken.Token, resetPasswordDTO.NewPassword);

            if (!result.Succeeded)
            {
                var errorDescription = string.Join("; ", result.Errors.Select(e => e.Description));

                return new ApiResponse()
                {
                    IsSuccess = false,
                    StatusCode = HttpStatusCode.NotFound,
                    ErrorMessage = errorDescription,
                    Result = null,
                };
            }

            resetPasswordToken.IsUsed = true;
            resetPasswordToken.ExpiresAt = DateTime.Now;

            _context.ResetPasswordTokens.Update(resetPasswordToken);
            await _context.SaveChangesAsync();

            return new ApiResponse()
            {
                IsSuccess = true,
                StatusCode = HttpStatusCode.OK,
            };
        }

        public async Task<TokenResponseDTO?> ExternalLoginAsync(ExternalLoginDTO loginDTO)
        {
            var user = await _userManager.FindByLoginAsync(loginDTO.Provider, loginDTO.ProviderUserId);

            if (user == null)
            {
                user = await _userManager.FindByEmailAsync(loginDTO.Email);
                if (user == null)
                {
                    user = new ApplicationUser
                    {
                        UserName = loginDTO.Email,
                        Email = loginDTO.Email,
                        EmailConfirmed = true,
                        FullName = loginDTO.Name,
                        PhoneNumber = loginDTO.PhoneNumber,
                    };
                    var createResult = await _userManager.CreateAsync(user);
                    if (!createResult.Succeeded) return null;
                }

                var loginInfo = new UserLoginInfo(loginDTO.Provider, loginDTO.ProviderUserId, loginDTO.Provider);
                var addLoginResult = await _userManager.AddLoginAsync(user, loginInfo);
                if (!addLoginResult.Succeeded) return null;
            }

            return new TokenResponseDTO()
            {
                AccessToken = await GenerateAccessToken(user),
                RefreshToken = await SaveRefreshTokenAsync(user),
                AccessTokenExpires = DateTime.UtcNow.AddMinutes(30),
                RefreshTokenExpires = DateTime.UtcNow.AddDays(7)
            };

        }

        public async Task<ApiResponse?> GenerateRemoveAccountTokenAsync(string Email)
        {
            ApplicationUser? applicationUser = await _userManager.FindByEmailAsync(Email);

            if (applicationUser == null)
            {
                return new ApiResponse()
                {
                    IsSuccess = false,
                    StatusCode = HttpStatusCode.NotFound,
                    ErrorMessage = "No user with this email found",
                    Result = null,
                };
            }

            RemoveAccountToken removeAccountToken = new RemoveAccountToken()
            {
                UserId = applicationUser.Id,
                ExpiresAt = DateTime.Now.AddMinutes(15),
                Token = await _userManager.GeneratePasswordResetTokenAsync(applicationUser),
                ApplicationUser = applicationUser
            };

            _context.RemoveAccountTokens.Add(removeAccountToken);
            await _context.SaveChangesAsync();

            return new ApiResponse()
            {
                IsSuccess = true,
                StatusCode = HttpStatusCode.OK,
                Result = removeAccountToken,
            };
        }
        public async Task<ApiResponse?> RemoveAccountAsync(RemoveAccountDTO removeAccountDTO, string userId)
        {

            RemoveAccountToken? removeAccountToken =
               await _context.RemoveAccountTokens.FirstOrDefaultAsync(t => t.Id == removeAccountDTO.TokenId);

            if (removeAccountToken == null || removeAccountToken.IsUsed == true)
                return new ApiResponse()
                {
                    IsSuccess = false,
                    StatusCode = HttpStatusCode.NotFound,
                    ErrorMessage = "Invaild Token !",
                    Result = null,
                };

            if (removeAccountToken.UserId != userId)
                return new ApiResponse()
                {
                    IsSuccess = false,
                    StatusCode = HttpStatusCode.NotFound,
                    ErrorMessage = "You Must Be Logged Into this Account To Delete It !",
                    Result = null,
                };

            if (removeAccountToken.ExpiresAt <= DateTime.Now)
                return new ApiResponse()
                {
                    IsSuccess = false,
                    StatusCode = HttpStatusCode.NotFound,
                    ErrorMessage = "Expired Token !",
                    Result = null,
                };

            ApplicationUser? applicationUser = await _context.ApplicationUsers
                .FirstOrDefaultAsync(a => a.Id == removeAccountToken.UserId);

            if (applicationUser == null)
                return new ApiResponse()
                {
                    ErrorMessage = "User not found",
                    IsSuccess = false,
                };
            var userLogins = await _userManager.GetLoginsAsync(applicationUser);
            bool hasExternalLogins = userLogins.Any();

            if (!hasExternalLogins)
            {
                if(String.IsNullOrEmpty(removeAccountDTO.Password))
                    return new ApiResponse()
                    {
                        ErrorMessage = "Password Is Required !",
                        IsSuccess = false,
                    };

                bool result = await _userManager.CheckPasswordAsync(applicationUser, removeAccountDTO.Password);

                if (!result)
                    return new ApiResponse()
                    {
                        ErrorMessage = "Wrong Password",
                        IsSuccess = false,
                    };
            }

            var deleted = await _userManager.DeleteAsync(applicationUser);

            if (!deleted.Succeeded)
                return new ApiResponse()
                {
                    ErrorMessage = "Failed to delete account",
                    IsSuccess = false,
                };

            await RevokeAllUserRefreshTokensAsync(removeAccountToken.UserId);
            return new ApiResponse { IsSuccess = true };

        }

        private bool UserNameUnique(string userName)
        {
            bool result = false;
            ApplicationUser? applicationUser = _context.ApplicationUsers.FirstOrDefault(u => u.UserName == userName);

            if (applicationUser == null)
            {
                result = true;
            }
            return result;
        }

        private async Task<string> GenerateAccessToken(ApplicationUser applicationUser)
        {
            var userRoles = await _userManager.GetRolesAsync(applicationUser);

            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, applicationUser.FullName),
                new Claim(ClaimTypes.NameIdentifier, applicationUser.Id,ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, applicationUser.Id)
            };

            foreach (var role in userRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config.GetValue<string>("AppSettings:SecretKey")));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);

            var tokenDescriptor = new JwtSecurityToken
                (
                    issuer: _config.GetValue<string>("AppSettings:Issuer"),
                    audience: _config.GetValue<string>("AppSettings:Audience"),
                    claims: claims,
                    signingCredentials: creds,
                    expires: DateTime.Now.AddMinutes(30)
                );

            string finalToken = new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);

            return finalToken;

        }

        private async Task<string> GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private async Task<string> SaveRefreshTokenAsync(ApplicationUser user, string? ipAddress = null)
        {
            RefreshToken refreshToken = new RefreshToken()
            {
                Token = await GenerateRefreshToken(),
                UserId = user.Id,
                CreatedAt = DateTime.Now,
                ExpiresAt = DateTime.Now.AddDays(7),
                CreatedByIp = ipAddress ?? "Unknown"
            };

            await _context.AddAsync(refreshToken);
            await _context.SaveChangesAsync();

            return refreshToken.Token;
        }

        private string GetClientIpAddress()
        {
            return _httpContextAccessor?.HttpContext?.Connection?.RemoteIpAddress?.ToString() ?? "Unknown";
        }

        private async Task<bool> ValidateRefreshToken(RefreshToken refreshToken)
        {
            if (refreshToken == null || !refreshToken.IsActive || refreshToken.IsExpired) return false;

            return true;
        }

        public async Task<bool> RevokeRefreshTokenAsync(string refreshToken, string? ipAddress = null)
        {

            RefreshToken? refreshToken1 = await _context.RefreshTokens
                .FirstOrDefaultAsync(r => r.Token == refreshToken);

            if (refreshToken1 == null || !refreshToken1.IsActive) return false;

            refreshToken1.RevokedAt = DateTime.Now;
            refreshToken1.RevokedByIp = ipAddress ?? GetClientIpAddress();

            await _context.SaveChangesAsync();
            return true;

        }

        public async Task<bool> RevokeAllUserRefreshTokensAsync(string userId, string? ipAddress = null)
        {
            List<RefreshToken>? refreshTokens = await _context.RefreshTokens
                 .Where(r => r.UserId == userId && r.IsActive == true).ToListAsync();

            if (refreshTokens == null) return false;

            foreach (RefreshToken refreshToken in refreshTokens)
            {
                refreshToken.RevokedAt = DateTime.Now;
                refreshToken.RevokedByIp = ipAddress ?? GetClientIpAddress();
            }
            await _context.SaveChangesAsync();
            return true;
        }


    }
}
