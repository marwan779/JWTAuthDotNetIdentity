using JWTAuthDotNetIdentity.Models;

namespace JWTAuthDotNetIdentity.Services
{
    public interface IMailService
    {
        bool SendMail(MailData Mail_Data);
    }
}
