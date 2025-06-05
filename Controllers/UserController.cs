using System.Security.Claims;
using JWTAuthDotNetIdentity.Models;
using JWTAuthDotNetIdentity.Models.DTOs;
using JWTAuthDotNetIdentity.Models.Entities;
using JWTAuthDotNetIdentity.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthDotNetIdentity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IAuthService _authService;
        public ApiResponse? ApiResponse;
        public UserController(IAuthService authService)
        {
            _authService = authService;
        }


        [HttpPost("RegisterUser")]
        public async Task<IActionResult> RegisterAsync(RegisterDTO registerDTO)
        {
            if (registerDTO == null)
            {
                return BadRequest();
            }
            else
            {
                ApiResponse = await _authService.RegisterAsync(registerDTO);

                if (ApiResponse.IsSuccess == false)
                {
                    return BadRequest(ApiResponse.ErrorMessage);
                }
                else
                {

                    return Ok(ApiResponse);
                }

            }

        }


        [HttpPost("LoginUser")]
        public async Task<IActionResult> LoginAsync(LoginDTO loginDTO)
        {
            if (loginDTO == null)
            {
                return BadRequest();
            }
            else
            {
                ApiResponse = await _authService.LoginAsync(loginDTO);

                if (ApiResponse.IsSuccess == false)
                {
                    return BadRequest(ApiResponse.ErrorMessage);
                }
                else
                {

                    return Ok(ApiResponse);
                }

            }

        }

        [HttpPost("RefreshTokens")]
        public async Task<IActionResult> RefreshTokens(TokenRequestDTO tokenRequestDTO)
        {
            TokenResponseDTO? tokenResponse = await _authService.RefreshTokensAsync(tokenRequestDTO);

            if(tokenResponse == null || tokenResponse.RefreshToken == null || tokenResponse.AccessToken == null) 
                return Unauthorized("Invaild Refresh Token !");

            return Ok(tokenResponse);
        }

        [Authorize]
        [HttpPost("ChangePassword")]
        public async Task<IActionResult> ChangePassword(ChangePasswordDTO changePasswordDTO)
        {
            string? userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            ApiResponse = await _authService.ChangePasswordAsync(userId, changePasswordDTO);

            if(!ApiResponse.IsSuccess)
            {
                return BadRequest(ApiResponse.ErrorMessage);
            }

            return Ok(ApiResponse);
        }


        // For testing 

        [Authorize]
        [HttpGet("TestAuthentication")]
        public IActionResult YouAreAuthenticated()
        {
            return Ok("You Are Authenticated");
        }

        // For testing 


        [Authorize(Roles = "Admin")]
        [HttpGet("TestAuthorization")]
        public IActionResult YouAreAtuhorized()
        {
            return Ok("You Are an admin");
        }
    }
}
