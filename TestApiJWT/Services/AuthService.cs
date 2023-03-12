using TestApiJWT.Models;

namespace TestApiJWT.Services
{
    public class AuthService : IAuthService
    {
        public AuthService()
        {
        }

        public Task<AuthModel> RegisterAsync(RegisterModel registerModel)
        {
            throw new NotImplementedException();
        }
    }
}
