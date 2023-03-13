using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace TestApiJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Get()
        {
            await Task.Delay(new Random().Next(5) * 1000);

            return Ok(new
            {
                Data = "123456789",
                Message = "SUCCESS"
            });
        }
    }
}
