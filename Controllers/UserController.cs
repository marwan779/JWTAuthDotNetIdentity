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
        private readonly IMailService _mailService;
        public ApiResponse? ApiResponse;
        public UserController(IAuthService authService, IMailService mailService)
        {
            _authService = authService;
            _mailService = mailService;
        }


        [HttpPost("Register-User")]
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


        [HttpPost("Login-User")]
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

        [HttpPost("Refresh-Tokens")]
        public async Task<IActionResult> RefreshTokens(TokenRequestDTO tokenRequestDTO)
        {
            TokenResponseDTO? tokenResponse = await _authService.RefreshTokensAsync(tokenRequestDTO);

            if (tokenResponse == null || tokenResponse.RefreshToken == null || tokenResponse.AccessToken == null)
                return Unauthorized("Invaild Refresh Token !");

            return Ok(tokenResponse);
        }

        [HttpPost("Get-Reset-Password-Token")]
        public async Task<IActionResult> GetResetPasswordToken(string Email)
        {
            if (string.IsNullOrEmpty(Email)) return BadRequest();

            ApiResponse = await _authService.GenerateResetPasswordTokenAsync(Email);

            if (!ApiResponse.IsSuccess) return BadRequest(ApiResponse.ErrorMessage);

            ResetPasswordToken resetPasswordToken = (ResetPasswordToken)ApiResponse.Result;


            MailData mailData = new MailData()
            {
                EmailToId = Email,
                EmailToName = resetPasswordToken.ApplicationUser.UserName,
                EmailSubject = "Reset Your Password",
                EmailBody = $@"
                Hello {resetPasswordToken.ApplicationUser.UserName},

                You recently requested to reset your password.

                Here is your password reset token:

                {resetPasswordToken.Id}

                This token will expire on {resetPasswordToken.ExpiresAt:u} and can only be used once.

                To complete the password reset, copy this token and paste it into the reset form in the app or website.

                If you did not request this, please ignore this message.

                Thanks,  
                Auth Team"
            };

            bool result = _mailService.SendMail(mailData);

            if (!result) return BadRequest();

            return Ok(result);

        }

        [HttpPost("Reset-Password")]
        public async Task<IActionResult> ResetPassword(ResetPasswordDTO resetPasswordDTO)
        {
            if (resetPasswordDTO.NewPassword == null || resetPasswordDTO.TokenId == null) return BadRequest();

            ApiResponse = await _authService.ResetPasswordAsync(resetPasswordDTO);

            if (!ApiResponse.IsSuccess)
                return BadRequest(ApiResponse.ErrorMessage);

            return Ok(ApiResponse);
        }

        [Authorize]
        [HttpPost("Change-Password")]
        public async Task<IActionResult> ChangePassword(ChangePasswordDTO changePasswordDTO)
        {
            string? userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            ApiResponse = await _authService.ChangePasswordAsync(userId, changePasswordDTO);

            if (!ApiResponse.IsSuccess)
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
