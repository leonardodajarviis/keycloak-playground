# Keycloak.Net

Thư viện .NET 8 nhẹ nhàng để tích hợp xác thực Keycloak vào ứng dụng ASP.NET Core với xác thực JWT Bearer token và hỗ trợ token introspection tùy chọn.

> **⚠️ Cảnh báo: Phiên bản Alpha**  
> Đây là **phiên bản alpha (1.0.0-alpha.1)** và không khuyến khích sử dụng trong môi trường production. API có thể thay đổi mà không cần thông báo trước. Sử dụng với trách nhiệm của bạn và vui lòng báo cáo bất kỳ vấn đề nào bạn gặp phải.

## Tính năng

- 🔐 Xác thực JWT Bearer token với Keycloak
- ✅ Hỗ trợ token introspection để tăng cường bảo mật
- 🎯 Cung cấp user context tích hợp với ánh xạ claims
- ⚙️ Tùy chọn cấu hình linh hoạt
- 🛡️ Hỗ trợ xử lý lỗi tùy chỉnh
- 🏥 Khả năng kiểm tra sức khỏe hệ thống
- 📦 Phụ thuộc tối thiểu

## Cài đặt

Thêm package reference vào project của bạn:

```xml
<PackageReference Include="Keycloak.Net" Version="1.0.0-alpha.1" />
```

Hoặc sử dụng .NET CLI:

```bash
dotnet add package Keycloak.Net
```

## Bắt đầu nhanh

### 1. Cấu hình

Thêm cấu hình Keycloak vào `appsettings.json`:

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

#### Các tùy chọn cấu hình

| Thuộc tính | Kiểu | Bắt buộc | Mô tả |
|------------|------|----------|-------|
| `Authority` | string | Có | URL của realm Keycloak (ví dụ: `https://keycloak.example.com/realms/myrealm`) |
| `Audience` | string | Có | Client ID cho ứng dụng của bạn |
| `ClientSecret` | string | Có* | Client secret để thực hiện token introspection (*bắt buộc nếu sử dụng introspection) |
| `RequireHttpsMetadata` | bool | Không | Có yêu cầu HTTPS cho metadata endpoint hay không (mặc định: `false`) |
| `ValidAudiences` | string[] | Không | Danh sách các audience hợp lệ để xác thực token (mặc định: `[Audience]`) |

### 2. Đăng ký Services

Trong `Program.cs`, thêm các dịch vụ xác thực Keycloak:

```csharp
using Keycloak.Net.Extensions;

var builder = WebApplication.CreateBuilder(args);

// Thêm xác thực Keycloak
builder.Services.AddKeycloakAuthentication(builder.Configuration);

// Tùy chọn: Thêm user context provider
builder.Services.AddKeycloakUserProvider<KeycloakUserContext<Guid>, Guid>();

builder.Services.AddControllers();

var app = builder.Build();

// Thêm authentication và authorization middleware
app.UseAuthentication();
app.UseAuthorization();

// Tùy chọn: Thêm Keycloak authentication middleware để thực hiện token introspection
app.UseKeycloakAuth(options =>
{
    options.EnableIntrospection = true; // Bật token introspection (mặc định: true)
});

app.MapControllers();
app.Run();
```

### 3. Bảo vệ Endpoints

Sử dụng attribute `[Authorize]` chuẩn để bảo vệ endpoints:

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
        return Ok("Dữ liệu chỉ dành cho admin");
    }
}
```

## Sử dụng nâng cao

### Custom User Context

Tạo một custom user context để ánh xạ claims từ Keycloak vào domain model của bạn:

```csharp
public class MyUserContext : KeycloakUserContext<Guid>
{
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string Department { get; set; } = string.Empty;
}

// Đăng ký custom user provider
services.AddKeycloakUserProvider<MyUserContext, Guid>();
```

Sau đó inject và sử dụng trong controllers:

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

Sử dụng `IKeycloakService` để thực hiện token introspection thủ công:

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

Kiểm tra xem Keycloak server có khả dụng không:

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
        return isHealthy ? Ok("Keycloak đang hoạt động tốt") : ServiceUnavailable("Keycloak không khả dụng");
    }
}
```

### Xử lý lỗi tùy chỉnh

Cấu hình các trình xử lý lỗi tùy chỉnh cho các lỗi xác thực:

```csharp
app.UseKeycloakAuth(options =>
{
    options.EnableIntrospection = true;
    
    // Xử lý lỗi xác thực tùy chỉnh
    options.OnAuthenticationFailed = async (context, failureContext) =>
    {
        context.Response.StatusCode = 401;
        context.Response.ContentType = "application/json";
        
        await context.Response.WriteAsJsonAsync(new
        {
            error = "authentication_failed",
            message = "Token của bạn không hợp lệ hoặc đã hết hạn",
            code = failureContext.ErrorCode
        });
    };
    
    // Xử lý lỗi hạ tầng tùy chỉnh
    options.OnInfrastructureFailed = async (context, failureContext) =>
    {
        context.Response.StatusCode = 503;
        context.Response.ContentType = "application/json";
        
        await context.Response.WriteAsJsonAsync(new
        {
            error = "service_unavailable",
            message = "Không thể kết nối đến dịch vụ xác thực"
        });
    };
    
    // Ánh xạ status code tùy chỉnh
    options.GetStatusCode = errorCode => errorCode switch
    {
        "TOKEN_EXPIRED" => 401,
        "TOKEN_INVALID" => 401,
        "CLIENT_AUTH_FAILED" => 503,
        _ => 401
    };
    
    // Ánh xạ thông báo lỗi tùy chỉnh
    options.GetErrorMessage = errorCode => errorCode switch
    {
        "TOKEN_EXPIRED" => "Phiên của bạn đã hết hạn. Vui lòng đăng nhập lại.",
        "TOKEN_INVALID" => "Token xác thực không hợp lệ.",
        "CLIENT_AUTH_FAILED" => "Dịch vụ xác thực tạm thời không khả dụng.",
        _ => "Xác thực thất bại."
    };
});
```

## Tùy chọn Authentication Middleware

Middleware `UseKeycloakAuth` chấp nhận các tùy chọn sau:

| Thuộc tính | Kiểu | Mặc định | Mô tả |
|------------|------|----------|-------|
| `EnableIntrospection` | bool | `true` | Bật token introspection để xác thực bổ sung |
| `OnAuthenticationFailed` | Func | `null` | Trình xử lý tùy chỉnh cho lỗi xác thực (token không hợp lệ/hết hạn) |
| `OnInfrastructureFailed` | Func | `null` | Trình xử lý tùy chỉnh cho lỗi hạ tầng (lỗi kết nối) |
| `GetStatusCode` | Func | Ánh xạ mặc định | Ánh xạ mã lỗi sang HTTP status code |
| `GetErrorMessage` | Func | Ánh xạ mặc định | Ánh xạ mã lỗi sang thông báo thân thiện với người dùng |

## Mã lỗi

Thư viện sử dụng các mã lỗi sau:

| Mã lỗi | Mô tả | Status mặc định |
|--------|-------|-----------------|
| `TOKEN_EXPIRED` | Token đã hết hạn | 401 |
| `TOKEN_INVALID` | Token không hợp lệ hoặc sai định dạng | 401 |
| `TOKEN_INACTIVE` | Token không hoạt động (từ introspection) | 401 |
| `CLIENT_AUTH_FAILED` | Xác thực với Keycloak thất bại | 503 |
| `INTROSPECTION_FAILED` | Yêu cầu token introspection thất bại | 503 |
| `CONFIGURATION_ERROR` | Cấu hình Keycloak không hợp lệ | 500 |

## Thứ tự Middleware Pipeline

Để hoạt động đúng cách, đảm bảo middleware được thêm theo đúng thứ tự:

```csharp
app.UseRouting();           // 1. Routing
app.UseAuthentication();    // 2. Authentication (xác thực JWT)
app.UseKeycloakAuth();      // 3. Keycloak middleware (introspection)
app.UseAuthorization();     // 4. Authorization (kiểm tra role/policy)
app.MapControllers();       // 5. Endpoints
```

## Phụ thuộc

- Microsoft.AspNetCore.App (Framework)
- Microsoft.AspNetCore.Authentication.JwtBearer (8.0.7)
- Microsoft.IdentityModel.Protocols.OpenIdConnect (8.15.0)

## Yêu cầu

- .NET 8.0 trở lên
- ASP.NET Core 8.0 trở lên
- Keycloak server (bất kỳ phiên bản gần đây nào)

## Giấy phép

Dự án này được cấp phép theo giấy phép MIT.

## Hỗ trợ

Nếu có vấn đề, câu hỏi hoặc muốn đóng góp, vui lòng mở một issue trên repository của dự án.
