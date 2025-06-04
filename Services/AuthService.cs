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

namespace JWTAuthDotNetIdentity.Services
{
    public class AuthService : IAuthService
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _config;
        public AuthService(ApplicationDbContext context,
            UserManager<ApplicationUser> userManager,
            IConfiguration config)
        {
            _context = context;
            _userManager = userManager;
            _config = config;
        }

        public async Task<ApiResponse ?> LoginAsync(LoginDTO loginDTO)
        {
            if (loginDTO == null)
                return null;

            ApplicationUser? applicationUser = await _context.ApplicationUsers.FirstOrDefaultAsync(u => u.UserName == loginDTO.UserName);

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

            string token = await GenerateAccessToken(applicationUser);

            return new ApiResponse()
            {
                ErrorMessage = "",
                Result = token,
                IsSuccess = true,
                StatusCode = HttpStatusCode.OK
            };
        }

        public async Task<ApiResponse ?> RegisterAsync(RegisterDTO registerDTO)
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
                else if(existingEmailUser != null)
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
                    expires: DateTime.Now.AddDays(1)
                );

            string finalToken = new JwtSecurityTokenHandler().WriteToken(tokenDescriptor);

            return finalToken;

        }
    }
}
