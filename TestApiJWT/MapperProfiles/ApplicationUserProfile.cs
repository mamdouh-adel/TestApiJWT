using AutoMapper;
using TestApiJWT.Models;

namespace TestApiJWT.MapperProfiles
{
	public class ApplicationUserProfile : Profile
	{
		public ApplicationUserProfile()
		{
			CreateMap<RegisterModel, ApplicationUser>();
		}
	}
}
