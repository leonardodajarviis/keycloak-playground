using Keycloak.Net.Abstractions;
using Keycloak.Net.Example.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keycloak.Net.Example.Controllers;

[ApiController]
[Route("api/protected")]
[Authorize] // Requires authenticated user
public class ProtectedController : ControllerBase
{
    private readonly IKeycloakUserProvider<User, string> _userProvider;

    public ProtectedController(IKeycloakUserProvider<User, string> userProvider)
    {
        _userProvider = userProvider;
    }

    [HttpGet("me")]
    public IActionResult GetCurrentUser()
    {
        var user = _userProvider.GetCurrentUser();
        if (user == null)
        {
            return Unauthorized(new { message = "User is not authenticated" });
        }

        return Ok(new
        {
            id = user.Id,
            username = user.UserName,
            email = user.Email,
            roles = user.Roles
        });
    }

    [HttpGet("data")]
    public IActionResult GetProtectedData()
    {
        return Ok(new
        {
            message = "This is protected data",
            timestamp = DateTime.UtcNow,
            user = User.Identity?.Name
        });
    }

    [HttpGet("admin-only")]
    [Authorize(Policy = "AdminOnly")] // Requires 'admin' role
    public IActionResult GetAdminData()
    {
        return Ok(new
        {
            message = "This is admin-only data",
            timestamp = DateTime.UtcNow,
            user = User.Identity?.Name
        });
    }

    [HttpGet("premium")]
    [Authorize(Policy = "PremiumUser")] // Requires 'subscription=premium' claim
    public IActionResult GetPremiumContent()
    {
        return Ok(new
        {
            message = "This is premium content",
            timestamp = DateTime.UtcNow,
            user = User.Identity?.Name
        });
    }

    [HttpPost("echo")]
    public IActionResult Echo([FromBody] object data)
    {
        return Ok(new
        {
            receivedData = data,
            timestamp = DateTime.UtcNow,
            user = User.Identity?.Name
        });
    }
}
