using JWTAuthDotNetIdentity.Configurations;
using JWTAuthDotNetIdentity.Models;
using Microsoft.Extensions.Options;
using MimeKit;
using MailKit.Net.Smtp;
using MailKit.Security;

namespace JWTAuthDotNetIdentity.Services
{
    public class MailService : IMailService
    {
        MailSettings Mail_Settings = null;
        public MailService(IOptions<MailSettings> options)
        {
            Mail_Settings = options.Value;
        }
        public bool SendMail(MailData Mail_Data)
        {
            try
            {
                //MimeMessage - a class from Mimekit
                MimeMessage email_Message = new MimeMessage();

                MailboxAddress email_From = new MailboxAddress(Mail_Settings.Name, Mail_Settings.EmailId);

                email_Message.From.Add(email_From);

                MailboxAddress email_To = new MailboxAddress(Mail_Data.EmailToName, Mail_Data.EmailToId);

                email_Message.To.Add(email_To);

                email_Message.Subject = Mail_Data.EmailSubject;

                BodyBuilder emailBodyBuilder = new BodyBuilder();

                emailBodyBuilder.TextBody = Mail_Data.EmailBody;

                email_Message.Body = emailBodyBuilder.ToMessageBody();

                //this is the SmtpClient class from the Mailkit.Net.Smtp namespace, not the System.Net.Mail one
                SmtpClient MailClient = new SmtpClient();

                MailClient.Connect(Mail_Settings.Host, Mail_Settings.Port, SecureSocketOptions.StartTls);

                MailClient.Authenticate(Mail_Settings.EmailId, Mail_Settings.Password);

                MailClient.Send(email_Message);

                MailClient.Disconnect(true);

                MailClient.Dispose();

                return true;
            }
            catch (Exception ex)
            {
                // Exception Details
                return false;
            }
        }
    }
}
