using System.Net;

namespace JWTAuthDotNetIdentity.Models
{
    public class ApiResponse
    {
        public HttpStatusCode StatusCode { get; set; }

        public bool IsSuccess { get; set; } = true;

        public string ErrorMessage { get; set; } = string.Empty;
        public object? Result { get; set; }
    }
}
