# JWT Authentication with .NET Identity

## Overview

A complete Authentication & Authorization system built with ASP.NET Core 8, JWT, Google OAuth, and ASP.NET Identity. This API-first project supports secure login, token refresh, external authentication, password reset, password change, Email reset, Email Change and account removal — with token-based email flows for sensitive operations.

## 🚀 Features

- ✅ **JWT-based authentication & authorization**
- 🔐 Role-based identity management using ASP.NET Identity
- 🔄 **Refresh token mechanism** with full revoke/invalidate support
- 🛡️ Secure login with **Google OAuth**
- 🔁 **Password reset** via email token
- ❌ **Account removal** secured by email token + password (if local login)
- ✉️ Integrated **email service** for sending security-sensitive tokens
- 🌐 **Swagger UI** with JWT Bearer support
- 🧪 **CORS** & HTTPS enforced for modern client integration

## Project Structure

```
.
├── Controllers/
│   └── UserController.cs
├── Data/
│   └── ApplicationDbContext.cs
├── Models/
│   ├── DTOs/
│   │   ├── ApplicationUserDTO.cs
│   │   ├── ChangeEmailDTO.cs
│   │   ├── ChangePasswordDTO.cs
│   │   ├── ExternalLoginDTO.cs
│   │   ├── LoginDTO.cs
│   │   ├── RegisterDTO.cs
│   │   ├── RemoveAccountDTO.cs
│   │   ├── ResetPasswordDTO.cs
│   │   ├── TokenRequestDTO.cs
│   │   └── TokenResponseDTO.cs
│   ├── Entities/
│   │   ├── ApplicationUser.cs
│   │   ├── RefreshToken.cs
│   │   ├── RemoveAccountToken.cs
│   │   └── ResetPasswordToken.cs
│   ├── ApiResponse.cs
│   └── MailData.cs
├── Services/
│   ├── IAuthService.cs
│   ├── IMailService.cs
│   ├── AuthService.cs
│   └── MailService.cs
├── Configurations/
│   └── MailSettings.cs
├── Program.cs
└── appsettings.json
```

## Features

### Authentication
- **User Registration**: Create new accounts with validation
- **Login**: JWT token generation with 30-minute expiration
- **Refresh Tokens**: 7-day validity with automatic revocation
- **Google OAuth**: Social login integration
- **Logout**: Token revocation system

### Password Management
- Password change for authenticated users
- Password reset via email token
- Secure password requirements (6+ chars, uppercase, lowercase, digit, special char)

### Account Management
- Email change functionality
- Account deletion with confirmation
- Token-based security for sensitive operations

### Security
- Refresh token rotation
- IP address tracking for token usage
- Automatic token revocation
- Role-based authorization (User/Admin)

## API Endpoints

### Authentication
- `POST /api/User/Register-User` - Register a new user
- `POST /api/User/Login-User` - Login with credentials
- `POST /api/User/Refresh-Tokens` - Refresh access token
- `GET /api/User/login-google` - Initiate Google OAuth flow
- `GET /api/User/google-callback` - Google OAuth callback
- `POST /api/User/Logout` - Logout and revoke tokens

### Password Management
- `POST /api/User/Get-Reset-Password-Token` - Request password reset token
- `POST /api/User/Reset-Password` - Reset password with token
- `POST /api/User/Change-Password` - Change password (authenticated)

### Account Management
- `POST /api/User/Change-Email` - Change email (authenticated)
- `POST /api/User/Get-Remove-Account-Token` - Request account deletion token
- `POST /api/User/Remove-Account` - Delete account with token

### Testing
- `GET /api/User/TestAuthentication` - Test authentication
- `GET /api/User/TestAuthorization` - Test admin authorization

## Setup Instructions

1. **Prerequisites**:
   - .NET 8.0 SDK
   - SQL Server (or configure another database provider)
   - Google OAuth credentials (for social login)

2. **Configuration**:
   - Update `appsettings.json` with:
     - Database connection string
     - JWT secret key, issuer, and audience
     - Email server settings (for password reset emails)
     - Google OAuth credentials

3. **Database**:
   - Apply migrations: `dotnet ef database update`

4. **Running**:
   - `dotnet run`

## Dependencies

- ASP.NET Core 8.0
- Entity Framework Core
- Identity Framework
- JWT Authentication
- MailKit (for email)
- Google Authentication

## Security Considerations

- Always use HTTPS in production
- Keep JWT secret keys secure
- Regularly rotate JWT signing keys
- Implement rate limiting on authentication endpoints
- Store refresh tokens securely with expiration

## Example Requests

### Registration
```json
POST /api/User/Register-User
{
  "fullName": "John Doe",
  "userName": "johndoe",
  "email": "john@example.com",
  "phoneNumber": "1234567890",
  "password": "SecurePassword123!"
}
```

### Login
```json
POST /api/User/Login-User
{
  "userName": "johndoe",
  "password": "SecurePassword123!"
}
```

### Password Reset
```json
POST /api/User/Reset-Password
{
  "tokenId": "token-guid-here",
  "newPassword": "NewSecurePassword123!"
}
```

## Response Format

All responses follow the `ApiResponse` format:
```json
{
  "isSuccess": true,
  "statusCode": 200,
  "errorMessage": "",
  "result": { /* response data */ }
}
```

