using System.Security.Claims;
using JWTAuthDotNetIdentity.Models;
using JWTAuthDotNetIdentity.Models.DTOs;
using JWTAuthDotNetIdentity.Models.Entities;
using JWTAuthDotNetIdentity.Services;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Http.HttpResults;

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
                JWT Authentication .NET Identity"
            };

            bool result = _mailService.SendMail(mailData);

            if (!result) return BadRequest();

            return Ok("An email is sent to you with the required token, please check your inbox");

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

        [Authorize]
        [HttpPost("Get-Change-Email-Token")]
        public async Task<IActionResult> GetChangeEmailToken(ChangeEmailRequestDTO changeEmailRequestDTO)
        {
            string? userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            ApiResponse = await _authService.GenerateChangeEmailTokenAsync(userId, changeEmailRequestDTO);

            if (!ApiResponse.IsSuccess)
            {
                return BadRequest(ApiResponse.ErrorMessage);
            }


            ChangeEmailToken changeEmailToken = (ChangeEmailToken) ApiResponse.Result;

            MailData mailData = new MailData()
            {
                EmailToId = changeEmailRequestDTO.NewEmail,
                EmailToName = changeEmailToken.ApplicationUser.UserName,
                EmailSubject = "Change your email",
                EmailBody = $@"
                Hello {changeEmailToken.ApplicationUser.UserName},

                You recently requested to change your email.

                Here is your change email token:

                {changeEmailToken.Id}

                This token will expire on {changeEmailToken.ExpiresAt:u} and can only be used once.

                To complete the change email, copy this token and paste it into the change email form in the app or website.

                If you did not request this, please ignore this message.

                Thanks,  
                JWT Authentication .NET Identity"
            };

            bool mailResult = _mailService.SendMail(mailData);

            if (!mailResult) return BadRequest("Failed to send email");

            return Ok("An confirmation token is sent to your new email, please check your inbox");
        }

        [Authorize]
        [HttpPost("Confirm-Change-Email")]
        public async Task<IActionResult> ConfirmChangeEmail(ConfirmEmailChangeDTO confirmEmailChangeDTO)
        {
            string? userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            ApiResponse = await _authService.ConfirmEmailChangeAsync(userId, confirmEmailChangeDTO);

            if (!ApiResponse.IsSuccess)
                return BadRequest(ApiResponse.ErrorMessage);

            ApplicationUser applicationUser = (ApplicationUser) ApiResponse.Result;

            MailData newMailData = new MailData()
            {
                EmailToId = confirmEmailChangeDTO.NewEmail,
                EmailToName = applicationUser.UserName,
                EmailSubject = "Email address successfully changed",
                EmailBody = $@"
                Hello {applicationUser.UserName},
    
                Your email address has been successfully updated for your account.
    
                Account Details:
                • Previous email: {applicationUser.Email}
                • New email: {confirmEmailChangeDTO.NewEmail} (this email)
                • Changed on: {DateTime.UtcNow:u}
                • Account: {applicationUser.UserName}
    
                This change was completed after you successfully verified ownership of this email address.
    
                What this means:
                • You will now receive all account notifications at this email address
                • Use this email address for future logins
                • All security communications will be sent here
    
                If you did not make this change, please contact our support team immediately.
    
                For your security, we recommend:
                • Review your recent account activity
                • Ensure your account recovery information is up to date
                • Keep your password secure and unique
    
                Thank you for keeping your account information current.
    
                Thanks,  
                JWT Authentication .NET Identity"
            };

            bool newMailResult = _mailService.SendMail(newMailData);

            if (!newMailResult)
                return BadRequest("Failed to send email");

            return Ok("An confirmation emails is sent to your new email, please check your inbox");
        }

        [HttpGet("login-google")]
        public IActionResult LoginWithGoogle()
        {
            var redirectUrl = Url.Action("GoogleCallback", "User");
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }

        [HttpGet("google-callback")]
        public async Task<IActionResult> GoogleCallback()
        {
            // Use "External" instead of CookieAuthenticationDefaults.AuthenticationScheme
            var result = await HttpContext.AuthenticateAsync(IdentityConstants.ExternalScheme);
            if (!result.Succeeded)
                return Unauthorized("External authentication failed.");

            var claims = result.Principal.Identities.FirstOrDefault()?.Claims;
            var email = claims?.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
            var name = claims?.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
            var googleId = claims?.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
            var phoneNumber = claims?.FirstOrDefault(c => c.Type == ClaimTypes.MobilePhone)?.Value;

            var loginDto = new ExternalLoginDTO
            {
                Provider = "Google",
                ProviderUserId = googleId,
                Email = email,
                Name = name,
                PhoneNumber = phoneNumber
            };

            var jwt = await _authService.ExternalLoginAsync(loginDto);
            if (jwt == null)
                return BadRequest("JWT token not issued");

            // Optional: Clear the external cookie
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            return Ok(jwt); // You can also redirect to your frontend with the token in query string
        }

        [Authorize]
        [HttpPost("Logout")]
        public async Task<IActionResult> Logout(TokenRequestDTO tokenRequestDTO)
        {
            string? userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            if (String.IsNullOrEmpty(userId)) return BadRequest();

            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();

            if(tokenRequestDTO!= null || !String.IsNullOrEmpty(tokenRequestDTO.RefreshToken))
            {
                await _authService.RevokeRefreshTokenAsync(tokenRequestDTO.RefreshToken, ipAddress);
            }
            else
            {
                await _authService.RevokeAllUserRefreshTokensAsync(userId, ipAddress);
            }

            return Ok();
        }

        [Authorize]
        [HttpPost("Get-Remove-Account-Token")]
        public async Task<IActionResult> GetRemoveAccountToken(string Email)
        {
            if (string.IsNullOrEmpty(Email)) return BadRequest();

            ApiResponse = await _authService.GenerateRemoveAccountTokenAsync(Email);

            if (!ApiResponse.IsSuccess) return BadRequest(ApiResponse.ErrorMessage);

            RemoveAccountToken removeAccountToken = (RemoveAccountToken)ApiResponse.Result;


            MailData mailData = new MailData()
            {
                EmailToId = Email,
                EmailToName = removeAccountToken.ApplicationUser.UserName,
                EmailSubject = "Remove Your Account",
                EmailBody = $@"
                Hello {removeAccountToken.ApplicationUser.UserName},

                You recently requested to delete your account.

                Here is your account deletion token:

                {removeAccountToken.Id}

                This token will expire on {removeAccountToken.ExpiresAt:u} and can only be used once.

                To complete the account deletion, copy this token and paste it into the reset form in the app or website.

                If you did not request this, please ignore this message.
                
                Blease Not That Your Account Will Be Deleted Permanently !!!!

                Thanks,  
                JWT Authentication .NET Identity"
                };

            bool result = _mailService.SendMail(mailData);

            if (!result) return BadRequest();

            return Ok("An email is sent to you with the required token, please check your inbox");

        }

        [Authorize]
        [HttpPost("Remove-Account")]
        public async Task<IActionResult> RemoveAccount(RemoveAccountDTO removeAccountDTO)
        {
            if (removeAccountDTO.TokenId == null) return BadRequest();

            string? userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            ApiResponse = await _authService.RemoveAccountAsync(removeAccountDTO, userId);

            if (!ApiResponse.IsSuccess)
                return BadRequest(ApiResponse.ErrorMessage);

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
