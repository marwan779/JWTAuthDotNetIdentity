
# 🔐 JWTAuthDotNetIdentity

A complete Authentication & Authorization system built with **ASP.NET Core 8**, **JWT**, **Google OAuth**, and **ASP.NET Identity**. This API-first project supports secure login, token refresh, external authentication, password reset, and account removal — with token-based email flows for sensitive operations.

---

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

---

## 📂 Project Structure

```bash
.
├── Controllers/
│   └── UserController.cs
├── Data/
│   └── ApplicationDbContext.cs
├── Models/
│   ├── DTO/
│   ├── Entities/
│   └── Response/
├── Services/
│   ├── IAuthService.cs
│   ├── IMailService.cs
│   ├── AuthService.cs
│   └── MailService.cs
├── Configurations/
│   └── MailSettings.cs
├── Program.cs
└── appsettings.json
````

---

## ⚙️ Technologies

* [.NET 8](https://dotnet.microsoft.com/en-us/download/dotnet/8.0)
* ASP.NET Core Web API
* ASP.NET Identity
* JWT (Json Web Tokens)
* Google OAuth (via `Microsoft.AspNetCore.Authentication.Google`)
* Entity Framework Core (SQL Server)
* Swagger / Swashbuckle
* CORS middleware
* MailKit / SMTP

---

## 🔑 Authentication Workflow

### 🔸 Register & Login (Local)

* POST `/api/user/register`
* POST `/api/user/login` → Returns JWT + Refresh Token

### 🔸 Google OAuth Login

* GET `/api/user/login-google` → Redirect to Google
* GET `/api/user/google-callback` → Retrieves Google profile and returns JWT

### 🔄 Refresh Token

* POST `/api/user/refresh-token`

### 📨 Reset Password

* POST `/api/user/generate-reset-password-token`
* POST `/api/user/reset-password`

### ❌ Remove Account

* POST `/api/user/generate-remove-account-token`
* POST `/api/user/remove-account`

### 🔒 Change Password

* POST `/api/user/Change-Password`

### 🔒 Change Email

* POST `/api/user/Change-Email`

---

## ✉️ Email Sender

Implements `IMailService` to send transactional emails:

* **Reset password link**
* **Remove account link**

**MailSettings** are configured in `appsettings.json`:



---

## 🔐 Swagger & JWT

1. Run the project:
   `https://localhost:7011/swagger`

2. Click "Authorize"
   Enter:

   ```
   Bearer <your_token_here>
   ```

3. Now all `[Authorize]` endpoints will be testable.

---

## 📦 NuGet Packages Used

* `Microsoft.AspNetCore.Identity.EntityFrameworkCore`
* `Microsoft.AspNetCore.Authentication.JwtBearer`
* `Microsoft.AspNetCore.Authentication.Google`
* `Microsoft.EntityFrameworkCore.SqlServer`
* `Swashbuckle.AspNetCore`
* `MailKit`
* `System.IdentityModel.Tokens.Jwt`


