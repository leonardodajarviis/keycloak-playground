# Keycloak.Net

A lightweight .NET 8 library for integrating Keycloak authentication into ASP.NET Core applications with JWT Bearer token validation and optional token introspection.

> **⚠️ Warning: Alpha Version**  
> This is an **alpha release (1.0.0-alpha.1)** and is not recommended for production use. APIs may change without notice. Use at your own risk and please report any issues you encounter.

## Features

- 🔐 JWT Bearer token authentication with Keycloak
- ✅ Token introspection support for enhanced security
- 🎯 Built-in user context provider with claims mapping
- ⚙️ Flexible configuration options
- 🛡️ Custom error handling support
- 🏥 Health check capabilities
- 📦 Minimal dependencies

## Installation

Add the package reference to your project:

```xml
<PackageReference Include="Keycloak.Net" Version="1.0.0-alpha.1" />
```

Or using the .NET CLI:

```bash
dotnet add package Keycloak.Net
```

## Quick Start

### 1. Configuration

Add Keycloak configuration to your `appsettings.json`:

```json
{
  "Keycloak": {
    "Authority": "https://your-keycloak-server/realms/your-realm",
    "Audience": "your-client-id",
    "ClientSecret": "your-client-secret",
    "RequireHttpsMetadata": true,
    "ValidAudiences": ["your-client-id", "additional-audience"]
  }
}
```

#### Configuration Options

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `Authority` | string | Yes | The Keycloak realm URL (e.g., `https://keycloak.example.com/realms/myrealm`) |
| `Audience` | string | Yes | The client ID for your application |
| `ClientSecret` | string | Yes* | Client secret for token introspection (*required if using introspection) |
| `RequireHttpsMetadata` | bool | No | Whether HTTPS is required for metadata endpoint (default: `false`) |
| `ValidAudiences` | string[] | No | List of valid audiences for token validation (defaults to `[Audience]`) |

### 2. Register Services

In your `Program.cs`, add the Keycloak authentication services:

```csharp
using Keycloak.Net.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Add Keycloak authentication
builder.Services.AddKeycloakAuthentication(builder.Configuration);

// Optional: Add user context provider
builder.Services.AddKeycloakUserProvider<KeycloakUserContext<Guid>, Guid>();

builder.Services.AddControllers();

var app = builder.Build();

// Add authentication and authorization middleware
app.UseAuthentication();
app.UseAuthorization();

// Optional: Add Keycloak authentication middleware for token introspection
app.UseKeycloakAuth(options =>
{
    options.EnableIntrospection = true; // Enable token introspection (default: true)
});

app.MapControllers();
app.Run();
```

### 3. Protect Your Endpoints

Use the standard `[Authorize]` attribute to protect your endpoints:

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class ProtectedController : ControllerBase
{
    [Authorize]
    [HttpGet]
    public IActionResult GetProtectedData()
    {
        var username = User.Identity?.Name;
        var roles = User.Claims
            .Where(c => c.Type == ClaimTypes.Role)
            .Select(c => c.Value);
            
        return Ok(new { username, roles });
    }
    
    [Authorize(Roles = "admin")]
    [HttpGet("admin")]
    public IActionResult GetAdminData()
    {
        return Ok("Admin only data");
    }
}
```

## Advanced Usage

### Custom User Context

Create a custom user context to map Keycloak claims to your domain model:

```csharp
public class MyUserContext : KeycloakUserContext<Guid>
{
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string Department { get; set; } = string.Empty;
}

// Register the custom user provider
services.AddKeycloakUserProvider<MyUserContext, Guid>();
```

Then inject and use it in your controllers:

```csharp
[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    private readonly IKeycloakUserProvider<MyUserContext, Guid> _userProvider;
    
    public UserController(IKeycloakUserProvider<MyUserContext, Guid> userProvider)
    {
        _userProvider = userProvider;
    }
    
    [Authorize]
    [HttpGet("profile")]
    public IActionResult GetProfile()
    {
        var user = _userProvider.GetCurrentUser();
        return Ok(user);
    }
}
```

### Token Introspection

Use the `IKeycloakService` for manual token introspection:

```csharp
[ApiController]
[Route("api/[controller]")]
public class TokenController : ControllerBase
{
    private readonly IKeycloakService _keycloakService;
    
    public TokenController(IKeycloakService keycloakService)
    {
        _keycloakService = keycloakService;
    }
    
    [HttpPost("validate")]
    public async Task<IActionResult> ValidateToken([FromBody] string token)
    {
        var result = await _keycloakService.IntrospectTokenAsync(token);
        
        if (result.IsSuccess)
        {
            return Ok(new 
            { 
                active = result.Value.Active,
                username = result.Value.Username,
                expiresAt = result.Value.Exp
            });
        }
        
        return Unauthorized(new { error = result.ErrorCode, message = result.ErrorMessage });
    }
}
```

### Health Checks

Check if your Keycloak server is reachable:

```csharp
[ApiController]
[Route("api/[controller]")]
public class HealthController : ControllerBase
{
    private readonly IKeycloakService _keycloakService;
    
    public HealthController(IKeycloakService keycloakService)
    {
        _keycloakService = keycloakService;
    }
    
    [HttpGet("keycloak")]
    public async Task<IActionResult> CheckKeycloak()
    {
        var isHealthy = await _keycloakService.CheckHealthAsync();
        return isHealthy ? Ok("Keycloak is healthy") : ServiceUnavailable("Keycloak is down");
    }
}
```

### Custom Error Handling

Configure custom error handlers for authentication failures:

```csharp
app.UseKeycloakAuth(options =>
{
    options.EnableIntrospection = true;
    
    // Custom authentication failure handler
    options.OnAuthenticationFailed = async (context, failureContext) =>
    {
        context.Response.StatusCode = 401;
        context.Response.ContentType = "application/json";
        
        await context.Response.WriteAsJsonAsync(new
        {
            error = "authentication_failed",
            message = "Your token is invalid or expired",
            code = failureContext.ErrorCode
        });
    };
    
    // Custom infrastructure failure handler
    options.OnInfrastructureFailed = async (context, failureContext) =>
    {
        context.Response.StatusCode = 503;
        context.Response.ContentType = "application/json";
        
        await context.Response.WriteAsJsonAsync(new
        {
            error = "service_unavailable",
            message = "Unable to connect to authentication service"
        });
    };
    
    // Custom status code mapping
    options.GetStatusCode = errorCode => errorCode switch
    {
        "TOKEN_EXPIRED" => 401,
        "TOKEN_INVALID" => 401,
        "CLIENT_AUTH_FAILED" => 503,
        _ => 401
    };
    
    // Custom error message mapping
    options.GetErrorMessage = errorCode => errorCode switch
    {
        "TOKEN_EXPIRED" => "Your session has expired. Please log in again.",
        "TOKEN_INVALID" => "Invalid authentication token.",
        "CLIENT_AUTH_FAILED" => "Authentication service is temporarily unavailable.",
        _ => "Authentication failed."
    };
});
```

## Authentication Middleware Options

The `UseKeycloakAuth` middleware accepts the following options:

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `EnableIntrospection` | bool | `true` | Enable token introspection for additional validation |
| `OnAuthenticationFailed` | Func | `null` | Custom handler for authentication failures (invalid/expired tokens) |
| `OnInfrastructureFailed` | Func | `null` | Custom handler for infrastructure failures (connection errors) |
| `GetStatusCode` | Func | Default mapper | Maps error codes to HTTP status codes |
| `GetErrorMessage` | Func | Default mapper | Maps error codes to user-friendly messages |

## Error Codes

The library uses the following error codes:

| Error Code | Description | Default Status |
|------------|-------------|----------------|
| `TOKEN_EXPIRED` | Token has expired | 401 |
| `TOKEN_INVALID` | Token is invalid or malformed | 401 |
| `TOKEN_INACTIVE` | Token is not active (from introspection) | 401 |
| `CLIENT_AUTH_FAILED` | Failed to authenticate with Keycloak | 503 |
| `INTROSPECTION_FAILED` | Token introspection request failed | 503 |
| `CONFIGURATION_ERROR` | Invalid Keycloak configuration | 500 |

## Middleware Pipeline Order

For proper operation, ensure the middleware is added in the correct order:

```csharp
app.UseRouting();           // 1. Routing
app.UseAuthentication();    // 2. Authentication (JWT validation)
app.UseKeycloakAuth();      // 3. Keycloak middleware (introspection)
app.UseAuthorization();     // 4. Authorization (role/policy checks)
app.MapControllers();       // 5. Endpoints
```

## Dependencies

- Microsoft.AspNetCore.App (Framework)
- Microsoft.AspNetCore.Authentication.JwtBearer (8.0.7)
- Microsoft.IdentityModel.Protocols.OpenIdConnect (8.15.0)

## Requirements

- .NET 8.0 or higher
- ASP.NET Core 8.0 or higher
- Keycloak server (any recent version)

## License

This project is licensed under the MIT License.

## Support

For issues, questions, or contributions, please open an issue on the project repository.
