using Keycloak.Net.Abstractions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Keycloak.Net.Example.Controllers;

[ApiController]
[Route("api/public")]
[AllowAnonymous] // This controller allows anonymous access
public class PublicController : ControllerBase
{
    private readonly IKeycloakService _keycloakService;

    public PublicController(IKeycloakService keycloakService)
    {
        _keycloakService = keycloakService;
    }

    [HttpGet("health")]
    public IActionResult Health()
    {
        return Ok(new
        {
            status = "healthy",
            timestamp = DateTime.UtcNow
        });
    }

    [HttpGet("health/keycloak")]
    public async Task<IActionResult> CheckKeycloakHealth()
    {
        var isHealthy = await _keycloakService.CheckHealthAsync(HttpContext.RequestAborted);

        if (isHealthy)
        {
            return Ok(new
            {
                service = "keycloak",
                status = "healthy",
                message = "Keycloak server is reachable and operational",
                timestamp = DateTime.UtcNow
            });
        }

        return StatusCode(StatusCodes.Status503ServiceUnavailable, new
        {
            service = "keycloak",
            status = "unhealthy",
            message = "Keycloak server is not reachable or not responding",
            timestamp = DateTime.UtcNow
        });
    }

    [HttpGet("health/full")]
    public async Task<IActionResult> FullHealthCheck()
    {
        var keycloakHealthy = await _keycloakService.CheckHealthAsync(HttpContext.RequestAborted);
        
        var healthStatus = new
        {
            application = new
            {
                status = "healthy",
                uptime = DateTime.UtcNow - System.Diagnostics.Process.GetCurrentProcess().StartTime.ToUniversalTime()
            },
            dependencies = new
            {
                keycloak = new
                {
                    status = keycloakHealthy ? "healthy" : "unhealthy",
                    reachable = keycloakHealthy
                }
            },
            overall = keycloakHealthy ? "healthy" : "degraded",
            timestamp = DateTime.UtcNow
        };

        var statusCode = keycloakHealthy 
            ? StatusCodes.Status200OK 
            : StatusCodes.Status503ServiceUnavailable;

        return StatusCode(statusCode, healthStatus);
    }

    [HttpGet("info")]
    public IActionResult Info()
    {
        return Ok(new
        {
            application = "Keycloak.Net Example API",
            version = "1.0.0",
            description = "Demo API showing Keycloak authentication integration"
        });
    }
}
