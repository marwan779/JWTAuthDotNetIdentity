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
