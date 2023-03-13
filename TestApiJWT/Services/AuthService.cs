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
		private readonly IMapper _mapper;
		private readonly JWT _jwt;

		public AuthService(UserManager<ApplicationUser> userManager, IMapper mapper, IOptions<JWT> jwt)
		{
			_userManager = userManager;
			_mapper = mapper;
			_jwt = jwt.Value;
		}

		public async Task<AuthModel> RegisterAsync(RegisterModel registerModel)
		{
			if (await _userManager.FindByEmailAsync(registerModel.Email) is not null)
			{
				return new AuthModel { Message = "Email is already registered!" };
			}

			if (await _userManager.FindByNameAsync(registerModel.UserName) is not null)
			{
				return new AuthModel { Message = "UserName is already registered!" };
			}

			var user = _mapper.Map<ApplicationUser>(registerModel);

			var result = await _userManager.CreateAsync(user, registerModel.Password);
			if (!result.Succeeded)
			{
				var errors = string.Join(',', result.Errors);
				return new AuthModel { Message = errors };
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
			var roleClamis = new List<Claim>();

			Array.ForEach(userRoles.ToArray(), role => roleClamis.Add(new Claim("roles", role)));

			var claims = new[]
			{
				new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
				new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
				new Claim(JwtRegisteredClaimNames.Email, user.Email),
				new Claim("uid", user.Id)
			}
			.Union(userClaims)
			.Union(roleClamis);

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
	}
}