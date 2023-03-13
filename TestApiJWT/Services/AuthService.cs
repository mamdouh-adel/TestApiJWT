using System.Net.Mime;
using System.Net.Mail;
using System;
using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TestApiJWT.Helpers;
using TestApiJWT.Models;

namespace TestApiJWT.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IMapper _mapper;
        private readonly JWT _jwt;

        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IMapper mapper, IOptions<JWT> jwt)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _mapper = mapper;
            _jwt = jwt.Value;
        }

        public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
        {
            AuthModel authModel = new();

            ApplicationUser user = await _userManager.FindByEmailAsync(model.Email);
            if (user is null || !await _userManager.CheckPasswordAsync(user, model.Password))
            {
                authModel.Message = "Invalid Email or Password";
                return authModel;
            }

            IList<string> roles = await _userManager.GetRolesAsync(user);
            JwtSecurityToken jwtToken = await this.CreateJwtToken(user);

            authModel.IsAuthenticated = true;
            authModel.Email = user.Email;
            authModel.Username = user.UserName;
            authModel.ExpiresOn = jwtToken.ValidTo;
            authModel.Roles = roles.ToList();
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtToken);

            return authModel;
        }

        private static bool IsValidEmail(string email)
        {
            var valid = true;

            try
            {
                var emailAddress = new MailAddress(email);
            }
            catch
            {
                valid = false;
            }

            return valid;
        }

        public async Task<AuthModel> RegisterAsync(RegisterModel registerModel)
        {
            if (await _userManager.FindByEmailAsync(registerModel.Email) is not null)
            {
                return new AuthModel { Message = "Email is already registered!" };
            }

            if (!IsValidEmail(registerModel.Email))
            {
                return new AuthModel { Message = "Invalid email" };
            }

            if (await _userManager.FindByNameAsync(registerModel.UserName) is not null)
            {
                return new AuthModel { Message = "UserName is already registered!" };
            }

            var user = _mapper.Map<ApplicationUser>(registerModel);

            var result = await _userManager.CreateAsync(user, registerModel.Password);
            if (!result.Succeeded)
            {
                StringBuilder errorsSb = new StringBuilder();
                Array.ForEach(result.Errors.ToArray(), err => errorsSb.Append(err.Description + ","));
                return new AuthModel { Message = errorsSb.ToString().Trim(',') };
            }

            await _userManager.AddToRoleAsync(user, "User");

            var jwtToken = await this.CreateJwtToken(user);

            return new AuthModel
            {
                Email = user.Email,
                IsAuthenticated = true,
                ExpiresOn = jwtToken.ValidTo,
                Roles = new List<string> { "User" },
                Username = user.UserName,
                Token = new JwtSecurityTokenHandler().WriteToken(jwtToken)
            };
        }

        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            var userClaims = await _userManager.GetClaimsAsync(user);
            var userRoles = await _userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            Array.ForEach(userRoles.ToArray(), role => roleClaims.Add(new Claim("roles", role)));

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken
            (
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddDays(_jwt.DurationInDays),
                signingCredentials: signingCredentials
            );

            return jwtSecurityToken;
        }

        public async Task<string> AddRoleAsync(AddRoleModel model)
        {
            ApplicationUser user = await _userManager.FindByIdAsync(model.UserId);

			if (user is null || !await _roleManager.RoleExistsAsync(model.Role))
			{
				return "Invalid userId or role";
			}

			if (await _userManager.IsInRoleAsync(user, model.Role))
			{
				return "User is already assigned to this role";
			}

			var result = await _userManager.AddToRoleAsync(user, model.Role);
			
			return result.Succeeded ? string.Empty : "Something went wrong";
        }
    }
}