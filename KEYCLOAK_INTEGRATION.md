# TÀI LIỆU TÍCH HỢP XÁC THỰC TẬP TRUNG (BACKEND PROXY FLOW)

## MỤC LỤC

- [1. TỔNG QUAN LUỒNG XÁC THỰC](#1-tổng-quan-luồng-xác-thực)
  - [Quy trình hoạt động](#quy-trình-hoạt-động)
  - [Sơ đồ luồng xác thực](#sơ-đồ-luồng-xác-thực)
- [2. CẤU HÌNH KEYCLOAK (SERVER SIDE)](#2-cấu-hình-keycloak-server-side)
- [3. CÁC ENDPOINT VÀ THÔNG SỐ GIAO TIẾP](#3-các-endpoint-và-thông-số-giao-tiếp)
  - [A. Endpoint Backend gọi Keycloak](#a-endpoint-backend-gọi-keycloak)
  - [B. Endpoint Backend dùng để Verify](#b-endpoint-backend-dùng-để-verify-xác-thực-lại)
  - [C. Endpoint Refresh Token](#c-endpoint-refresh-token)
  - [D. Endpoint Public Keys](#d-endpoint-public-keys-để-verify-jwt)
  - [E. Endpoint Logout](#e-endpoint-logout)
  - [F. Endpoint Đăng ký Tài khoản](#f-endpoint-đăng-ký-tài-khoản)
  - [G. Gán Roles cho User](#g-gán-roles-cho-user-admin-api)
- [4. QUY TRÌNH XỬ LÝ TẠI BACKEND](#4-quy-trình-xử-lý-tại-backend)
  - [Bước 1: Tiếp nhận và Chuyển tiếp (Login)](#bước-1-tiếp-nhận-và-chuyển-tiếp-login)
  - [Bước 2: Xác thực các Request tiếp theo](#bước-2-xác-thực-các-request-tiếp-theo)
  - [Bước 3: Trích xuất Roles và Claims từ JWT Token](#bước-3-trích-xuất-roles-và-claims-từ-jwt-token)
- [5. CẤU HÌNH BIẾN MÔI TRƯỜNG (.env)](#5-cấu-hình-biến-môi-trường-env)
- [6. TRIỂN KHAI CODE MẪU (.NET)](#6-triển-khai-code-mẫu-net)
  - [A. Model định nghĩa](#a-model-định-nghĩa)
  - [B. Service xử lý Keycloak](#b-service-xử-lý-keycloak)
  - [C. Controller xử lý API](#c-controller-xử-lý-api)
  - [D. Middleware xác thực JWT](#d-middleware-xác-thực-jwt)
  - [E. Đăng ký Services trong Program.cs](#e-đăng-ký-services-trong-programcs)
  - [F. Phân quyền với Roles và Claims](#f-phân-quyền-với-roles-và-claims)
- [7. BẢO MẬT VÀ BEST PRACTICES](#7-bảo-mật-và-best-practices)
  - [A. Lưu trữ Token ở Client](#a-lưu-trữ-token-ở-client)
  - [B. Rate Limiting](#b-rate-limiting)
  - [C. Xử lý lỗi chi tiết](#c-xử-lý-lỗi-chi-tiết)
  - [D. HTTPS và CORS](#d-https-và-cors)
  - [E. Token Validation Best Practices](#e-token-validation-best-practices)
- [8. TESTING](#8-testing)
  - [A. Unit Tests cho KeycloakService](#a-unit-tests-cho-keycloakservice)
  - [B. Integration Tests](#b-integration-tests)
  - [C. Postman Collection - Test Backend API](#c-postman-collection---test-backend-api)
  - [D. Postman Collection - Test Keycloak Direct](#d-postman-collection---test-keycloak-direct)
  - [E. Hướng dẫn sử dụng Postman Collections](#e-hướng-dẫn-sử-dụng-postman-collections)
- [9. TROUBLESHOOTING](#9-troubleshooting)
  - [A. 401 Unauthorized khi login](#a-401-unauthorized-khi-login)
  - [B. Token validation failed](#b-token-validation-failed)
  - [C. CORS errors](#c-cors-errors)

---

## 1. TỔNG QUAN LUỒNG XÁC THỰC
Mô hình này cho phép ứng dụng Frontend/Mobile gửi thông tin đăng nhập trực tiếp về Backend. Backend sau đó đóng vai trò là Client ủy thác, giao tiếp với Keycloak để lấy Token.

### Quy trình hoạt động:
1. **Đăng nhập:** Client gửi `username` và `password` về API của Backend (ví dụ: `/api/login`).
2. **Ủy thác (Delegation):** Backend gửi yêu cầu xác thực tới Keycloak thông qua giao thức OAuth2.
3. **Cấp Token:** Keycloak xác thực và trả về bộ Token (`Access`, `Refresh`, `ID Token`) cho Backend.
4. **Phản hồi:** Backend trả bộ Token này về cho Client để sử dụng cho các yêu cầu API tiếp theo.

### Sơ đồ luồng xác thực:

```
┌─────────┐          ┌─────────┐            ┌──────────┐
│ Client  │          │ Backend │            │ Keycloak │
│(Web/App)│          │   API   │            │  Server  │
└────┬────┘          └────┬────┘            └────┬─────┘
     │                    │                      │
     │ 1. POST /api/login │                      │
     │ {username,password}│                      │
     ├───────────────────>│                      │
     │                    │                      │
     │                    │ 2. POST /token       │
     │                    │ (grant_type=password)│
     │                    ├────────────────────> │
     │                    │                      │
     │                    │ 3. Token Response    │
     │                    │ {access, refresh, id}│
     │                    │<─────────────────────┤
     │                    │                      │
     │ 4. Return Tokens   │                      │
     │<───────────────────┤                      │
     │                    │                      │
     │ 5. API Request     │                      │
     │ Authorization:     │                      │
     │ Bearer {token}     │                      │
     ├───────────────────>│                      │
     │                    │                      │
     │                    │ 6. Verify Token      │
     │                    │ (using public key)   │
     │                    │                      │
     │ 7. API Response    │                      │
     │<───────────────────┤                      │
     │                    │                      │
```



---

## 2. CẤU HÌNH KEYCLOAK (SERVER SIDE)

Để Backend có thể thực hiện việc xác thực thay cho người dùng, bạn cần cấu hình Client trên Keycloak như sau:

* **Client ID:** Định danh của Backend (ví dụ: `api-gateway`).
* **Access Type:** `confidential` (Bắt buộc để có Client Secret, tăng tính bảo mật cho Backend).
* **Direct Access Grants Enabled:** **On** (Cho phép xác thực bằng username/password trực tiếp).
* **Standard Flow Enabled:** **Off** (Vì không dùng giao diện đăng nhập của Keycloak).

---

## 3. CÁC ENDPOINT VÀ THÔNG SỐ GIAO TIẾP

### A. Endpoint Backend gọi Keycloak
Để lấy Token, Backend thực hiện POST request tới:
`POST {BASE_URL}/realms/{realm-name}/protocol/openid-connect/token`

**Nội dung Request (Content-Type: x-www-form-urlencoded):**
| Tham số | Giá trị |
| :--- | :--- |
| `grant_type` | `password` |
| `client_id` | `[tên_client_id_cua_backend]` |
| `client_secret` | `[ma_bi_mat_lay_tu_keycloak]` |
| `username` | `[user_tu_frontend]` |
| `password` | `[pass_tu_frontend]` |
| `scope` | `openid` (để lấy đủ các loại token) |

### B. Endpoint Backend dùng để Verify (Xác thực lại)
Sau khi Client đã có Token, các request tiếp theo sẽ gửi Token qua Header. Backend dùng endpoint này để kiểm tra token còn hiệu lực không:
`POST {BASE_URL}/realms/{realm-name}/protocol/openid-connect/token/introspect`

### C. Endpoint Refresh Token
Khi Access Token hết hạn, Client có thể dùng Refresh Token để lấy token mới mà không cần đăng nhập lại:
`POST {BASE_URL}/realms/{realm-name}/protocol/openid-connect/token`

**Nội dung Request (Content-Type: x-www-form-urlencoded):**
| Tham số | Giá trị |
| :--- | :--- |
| `grant_type` | `refresh_token` |
| `client_id` | `[tên_client_id_cua_backend]` |
| `client_secret` | `[ma_bi_mat_lay_tu_keycloak]` |
| `refresh_token` | `[refresh_token_nhan_duoc]` |

### D. Endpoint Public Keys (để verify JWT)
Backend lấy public key để verify chữ ký JWT offline:
`GET {BASE_URL}/realms/{realm-name}/protocol/openid-connect/certs`

### E. Endpoint Logout
Khi người dùng đăng xuất, Backend cần gọi endpoint này để thu hồi (revoke) Refresh Token và kết thúc session trên Keycloak:
`POST {BASE_URL}/realms/{realm-name}/protocol/openid-connect/logout`

**Nội dung Request (Content-Type: x-www-form-urlencoded):**
| Tham số | Giá trị |
| :--- | :--- |
| `client_id` | `[tên_client_id_cua_backend]` |
| `client_secret` | `[ma_bi_mat_lay_tu_keycloak]` |
| `refresh_token` | `[refresh_token_can_revoke]` |

**Lưu ý:**
- Sau khi logout thành công, tất cả tokens liên quan đến session sẽ bị vô hiệu hóa
- Client nên xóa tất cả tokens đã lưu (access_token, refresh_token, id_token)
- Response trả về status 204 No Content nếu thành công

### F. Endpoint Đăng ký Tài khoản
Backend tạo user mới trong Keycloak thông qua Admin REST API:
`POST {BASE_URL}/admin/realms/{realm-name}/users`

**Headers:**
| Header | Giá trị |
| :--- | :--- |
| `Authorization` | `Bearer [admin_access_token]` |
| `Content-Type` | `application/json` |

**Nội dung Request (JSON):**
```json
{
  "username": "newuser",
  "email": "user@example.com",
  "firstName": "John",
  "lastName": "Doe",
  "enabled": true,
  "emailVerified": false,
  "credentials": [
    {
      "type": "password",
      "value": "userPassword123",
      "temporary": false
    }
  ]
}
```

**Lưu ý quan trọng:**
- Endpoint này yêu cầu **Admin Access Token**, không phải user token thông thường
- Backend cần có service account hoặc admin user để lấy admin token
- Admin token được lấy qua endpoint token với `grant_type=client_credentials`
- Để lấy Admin Token:
  ```
  POST {BASE_URL}/realms/{realm-name}/protocol/openid-connect/token

  Body (x-www-form-urlencoded):
  - grant_type: client_credentials
  - client_id: [admin_client_id]
  - client_secret: [admin_client_secret]
  ```

**Cấu hình Client cho Admin API:**
- Trong Keycloak Admin Console, client cần có:
  - **Service Accounts Enabled**: ON
  - **Authorization Enabled**: ON (nếu cần)
  - **Service Account Roles**: Thêm role `manage-users` từ `realm-management`

**⚠️ Lưu ý Bảo mật quan trọng:**
- User mới được tạo sẽ **KHÔNG có roles mặc định** (trừ default roles của realm)
- User **KHÔNG thể tự gán roles** cho chính mình thông qua API đăng ký
- Chỉ có Admin hoặc Backend với quyền Admin mới có thể gán roles cho users
- Nếu cần user có role ngay khi đăng ký, Backend phải:
  1. Tạo user qua Admin API
  2. Gọi tiếp Admin API để gán role cho user vừa tạo
  3. Endpoint: `POST {BASE_URL}/admin/realms/{realm}/users/{userId}/role-mappings/realm`

**Tại sao User không thể tự gán Roles?**
- **Bảo mật**: Nếu user tự gán roles, ai cũng có thể tự phong mình làm admin
- **Phân quyền tập trung**: Roles phải được quản lý tập trung bởi administrators
- **Audit trail**: Mọi thay đổi về roles đều phải được theo dõi và kiểm soát
- **Principle of Least Privilege**: User chỉ được cấp quyền tối thiểu cần thiết

### G. Gán Roles cho User (Admin API)

Sau khi tạo user, Backend có thể gán roles thông qua Admin API:

#### G1. Lấy User ID sau khi tạo

Khi tạo user thành công, Keycloak trả về status `201 Created` với header `Location` chứa URL đến user mới:
```
Location: https://auth.example.com/admin/realms/my-realm/users/f8a7b234-5c6d-4e2f-8a9b-1c2d3e4f5g6h
```

User ID nằm ở cuối URL. Backend cần parse để lấy User ID này.

#### G2. Gán Realm Roles cho User

**Endpoint:**
```
POST {BASE_URL}/admin/realms/{realm-name}/users/{userId}/role-mappings/realm
```

**Headers:**
```
Authorization: Bearer [admin_access_token]
Content-Type: application/json
```

**Body (JSON):**
```json
[
  {
    "id": "role-uuid-here",
    "name": "user"
  }
]
```

**Lưu ý:**
- Cần cả `id` (UUID) và `name` của role
- Có thể gán nhiều roles cùng lúc (array)
- Phải lấy Role ID trước bằng endpoint GET roles

#### G3. Lấy danh sách Roles có sẵn

**Endpoint lấy tất cả Realm Roles:**
```
GET {BASE_URL}/admin/realms/{realm-name}/roles
```

**Response mẫu:**
```json
[
  {
    "id": "abc123-def456-ghi789",
    "name": "user",
    "description": "Standard user role"
  },
  {
    "id": "xyz987-uvw654-rst321",
    "name": "admin",
    "description": "Administrator role"
  }
]
```

#### G4. Quy trình đầy đủ để đăng ký User với Role

**Bước 1:** Backend nhận request đăng ký từ Client
**Bước 2:** Backend lấy Admin Token (client_credentials grant)
**Bước 3:** Backend tạo user qua Admin API
**Bước 4:** Parse User ID từ Location header
**Bước 5:** Backend gán role mặc định cho user (thường là role "user")
**Bước 6:** Trả về response thành công cho Client

**Quan trọng:**
- Các bước 2-5 phải thực hiện **phía Backend**
- Client chỉ gọi `/api/auth/register` với thông tin cơ bản
- Backend tự động gán role "user" mặc định cho mọi user đăng ký mới
- Admin roles chỉ được gán thủ công bởi administrators qua Keycloak Admin Console

#### G5. Phân biệt quyền hạn

| Ai? | Có thể làm gì? | Cách thức |
|-----|----------------|-----------|
| **User thông thường** | Đăng ký tài khoản | Gọi `/api/auth/register` |
| **User thông thường** | Đăng nhập, đổi mật khẩu | Các API công khai |
| **User thông thường** | ❌ KHÔNG thể gán/thay đổi roles | Bị cấm hoàn toàn |
| **Backend Service** | Tạo user và gán role mặc định | Dùng Admin Token với role `manage-users` |
| **Backend Service** | ❌ KHÔNG nên gán admin roles | Chỉ gán role "user" cơ bản |
| **Keycloak Admin** | Quản lý users, gán/thu hồi mọi roles | Keycloak Admin Console hoặc Admin API |

---

## 4. QUY TRÌNH XỬ LÝ TẠI BACKEND

### Bước 1: Tiếp nhận và Chuyển tiếp (Login)
* Nhận thông tin định danh từ Client.
* Gọi đến Keycloak Token Endpoint.
* Nếu Keycloak trả về lỗi (401/400), Backend trả về lỗi đăng nhập cho Client.
* Nếu thành công, trả về toàn bộ JSON nhận được từ Keycloak.

### Bước 2: Xác thực các Request tiếp theo
Khi Client gọi các API nghiệp vụ:
1. Trích xuất Bearer Token từ Header.
2. Kiểm tra chữ ký Token (Offline) bằng **Public Key** lấy từ endpoint `/certs`.
3. Kiểm tra tính hợp lệ của Token (`exp`, `iss`, `aud`).
4. Xử lý nghiệp vụ nếu hợp lệ.

### Bước 3: Trích xuất Roles và Claims từ JWT Token

Sau khi xác thực token thành công, Backend cần trích xuất thông tin user và phân quyền từ JWT token:

#### 3.1. Cấu trúc JWT Token từ Keycloak

JWT Token được chia thành 3 phần (cách nhau bởi dấu chấm):
```
Header.Payload.Signature
```

**Payload chứa Claims** (thông tin user và roles):
- **sub**: User ID (subject)
- **preferred_username**: Tên đăng nhập
- **email**: Email của user
- **name**: Tên đầy đủ
- **given_name**: Tên
- **family_name**: Họ
- **realm_access**: Chứa Realm Roles
- **resource_access**: Chứa Client Roles (roles cụ thể cho từng client)
- **exp**: Thời gian hết hạn (timestamp)
- **iat**: Thời gian phát hành (timestamp)
- **iss**: Issuer (Keycloak realm URL)

#### 3.2. Cách Backend lấy Roles và Claims

**Bước 1: Decode JWT Token**
- JWT là chuỗi Base64URL encoded
- Phần Payload (phần thứ 2) chứa tất cả claims
- Backend cần decode Base64URL để lấy JSON payload

**Bước 2: Parse JSON Payload**
- Chuyển đổi string JSON thành object
- Truy cập các properties để lấy thông tin

**Bước 3: Trích xuất Realm Roles**
- Tìm claim có key `realm_access`
- Bên trong có property `roles` là array chứa danh sách roles
- Ví dụ: `["admin", "user"]`

**Bước 4: Trích xuất Client Roles (nếu có)**
- Tìm claim có key `resource_access`
- Bên trong có object với key là client_id
- Mỗi client có property `roles` chứa roles riêng
- Ví dụ: `{ "backend-service": { "roles": ["api-admin"] } }`

**Bước 5: Tạo User Context**
- Lưu thông tin user và roles vào context của request
- Sử dụng Claims-based authentication của framework
- Gắn roles vào Principal/User object để sử dụng trong controllers

#### 3.3. Ví dụ cấu trúc Payload trong JWT

```json
{
  "sub": "f8a7b234-5c6d-4e2f-8a9b-1c2d3e4f5g6h",
  "preferred_username": "john.doe",
  "email": "john@example.com",
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "realm_access": {
    "roles": ["admin", "user", "offline_access"]
  },
  "resource_access": {
    "backend-service": {
      "roles": ["api-admin", "data-read"]
    },
    "account": {
      "roles": ["manage-account", "view-profile"]
    }
  },
  "exp": 1706543210,
  "iat": 1706542310,
  "iss": "https://auth.example.com/realms/my-project"
}
```

#### 3.4. Lưu ý quan trọng

**Về Security:**
- KHÔNG decode token mà không verify signature trước
- Luôn verify token bằng public key từ Keycloak trước khi tin tưởng claims
- Claims có thể bị giả mạo nếu không verify signature

**Về Performance:**
- Cache public keys từ Keycloak (thường 24h)
- Parse token chỉ 1 lần cho mỗi request
- Lưu claims vào request context để tái sử dụng

**Về Realm vs Client Roles:**
- **Realm Roles**: Roles chung cho toàn bộ realm, dùng cho nhiều applications
- **Client Roles**: Roles riêng cho từng client, giới hạn phạm vi trong 1 application
- Backend thường dùng Realm Roles cho đơn giản, hoặc Client Roles nếu cần isolation

#### 3.5. Sử dụng Roles để phân quyền

Sau khi có roles, Backend có thể:
1. **Kiểm tra Role trong Controller**: Trước khi xử lý logic, check xem user có role cần thiết không
2. **Áp dụng Authorization Policy**: Tạo policies dựa trên roles (ví dụ: AdminOnly policy)
3. **Filter data**: Giới hạn dữ liệu trả về dựa trên roles (admin thấy tất cả, user chỉ thấy của mình)
4. **Audit logging**: Log các hành động với thông tin user và role

---

## 5. CẤU HÌNH BIẾN MÔI TRƯỜNG (`.env`)

```bash
KEYCLOAK_BASE_URL="https://auth.example.com"
KEYCLOAK_REALM="my-project"
KEYCLOAK_CLIENT_ID="backend-service"
KEYCLOAK_CLIENT_SECRET="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

---

## 6. TRIỂN KHAI CODE MẪU (.NET)

### A. Model định nghĩa

```csharp
// Models/LoginRequest.cs
public class LoginRequest
{
    [Required]
    public string Username { get; set; }

    [Required]
    public string Password { get; set; }
}

// Models/TokenResponse.cs
public class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; }

    [JsonPropertyName("refresh_token")]
    public string RefreshToken { get; set; }

    [JsonPropertyName("id_token")]
    public string IdToken { get; set; }

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; }

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    [JsonPropertyName("refresh_expires_in")]
    public int RefreshExpiresIn { get; set; }
}

// Models/RefreshTokenRequest.cs
public class RefreshTokenRequest
{
    [Required]
    public string RefreshToken { get; set; }
}

// Models/LogoutRequest.cs
public class LogoutRequest
{
    [Required]
    public string RefreshToken { get; set; }
}

// Models/RegisterRequest.cs
public class RegisterRequest
{
    [Required]
    [StringLength(50, MinimumLength = 3)]
    public string Username { get; set; }

    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    [StringLength(100, MinimumLength = 8)]
    public string Password { get; set; }

    [StringLength(50)]
    public string FirstName { get; set; }

    [StringLength(50)]
    public string LastName { get; set; }
}

// Models/KeycloakUserCreateRequest.cs (DTO cho Keycloak Admin API)
public class KeycloakUserCreateRequest
{
    [JsonPropertyName("username")]
    public string Username { get; set; }

    [JsonPropertyName("email")]
    public string Email { get; set; }

    [JsonPropertyName("firstName")]
    public string FirstName { get; set; }

    [JsonPropertyName("lastName")]
    public string LastName { get; set; }

    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = true;

    [JsonPropertyName("emailVerified")]
    public bool EmailVerified { get; set; } = false;

    [JsonPropertyName("credentials")]
    public List<KeycloakCredential> Credentials { get; set; }
}

// Models/KeycloakCredential.cs
public class KeycloakCredential
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = "password";

    [JsonPropertyName("value")]
    public string Value { get; set; }

    [JsonPropertyName("temporary")]
    public bool Temporary { get; set; } = false;
}
```

### B. Service xử lý Keycloak

```csharp
// Services/KeycloakService.cs
public interface IKeycloakService
{
    Task<TokenResponse> LoginAsync(string username, string password);
    Task<TokenResponse> RefreshTokenAsync(string refreshToken);
    Task<bool> ValidateTokenAsync(string token);
    Task<bool> LogoutAsync(string refreshToken);
    Task<bool> RegisterAsync(RegisterRequest request);
    Task<string> GetAdminTokenAsync();
}

public class KeycloakService : IKeycloakService
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _configuration;
    private readonly ILogger<KeycloakService> _logger;

    private string BaseUrl => _configuration["KEYCLOAK_BASE_URL"];
    private string Realm => _configuration["KEYCLOAK_REALM"];
    private string ClientId => _configuration["KEYCLOAK_CLIENT_ID"];
    private string ClientSecret => _configuration["KEYCLOAK_CLIENT_SECRET"];

    public KeycloakService(
        HttpClient httpClient,
        IConfiguration configuration,
        ILogger<KeycloakService> logger)
    {
        _httpClient = httpClient;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<TokenResponse> LoginAsync(string username, string password)
    {
        var tokenEndpoint = $"{BaseUrl}/realms/{Realm}/protocol/openid-connect/token";

        var requestBody = new Dictionary<string, string>
        {
            { "grant_type", "password" },
            { "client_id", ClientId },
            { "client_secret", ClientSecret },
            { "username", username },
            { "password", password },
            { "scope", "openid" }
        };

        try
        {
            var response = await _httpClient.PostAsync(
                tokenEndpoint,
                new FormUrlEncodedContent(requestBody)
            );

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogError($"Keycloak login failed: {errorContent}");
                return null;
            }

            var content = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<TokenResponse>(content);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during Keycloak login");
            throw;
        }
    }

    public async Task<TokenResponse> RefreshTokenAsync(string refreshToken)
    {
        var tokenEndpoint = $"{BaseUrl}/realms/{Realm}/protocol/openid-connect/token";

        var requestBody = new Dictionary<string, string>
        {
            { "grant_type", "refresh_token" },
            { "client_id", ClientId },
            { "client_secret", ClientSecret },
            { "refresh_token", refreshToken }
        };

        try
        {
            var response = await _httpClient.PostAsync(
                tokenEndpoint,
                new FormUrlEncodedContent(requestBody)
            );

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Refresh token failed or expired");
                return null;
            }

            var content = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<TokenResponse>(content);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during token refresh");
            throw;
        }
    }

    public async Task<bool> ValidateTokenAsync(string token)
    {
        var introspectEndpoint = $"{BaseUrl}/realms/{Realm}/protocol/openid-connect/token/introspect";

        var requestBody = new Dictionary<string, string>
        {
            { "token", token },
            { "client_id", ClientId },
            { "client_secret", ClientSecret }
        };

        try
        {
            var response = await _httpClient.PostAsync(
                introspectEndpoint,
                new FormUrlEncodedContent(requestBody)
            );

            if (!response.IsSuccessStatusCode)
            {
                return false;
            }

            var content = await response.Content.ReadAsStringAsync();
            var result = JsonSerializer.Deserialize<JsonDocument>(content);

            return result.RootElement.GetProperty("active").GetBoolean();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during token validation");
            return false;
        }
    }

    public async Task<bool> LogoutAsync(string refreshToken)
    {
        var logoutEndpoint = $"{BaseUrl}/realms/{Realm}/protocol/openid-connect/logout";

        var requestBody = new Dictionary<string, string>
        {
            { "client_id", ClientId },
            { "client_secret", ClientSecret },
            { "refresh_token", refreshToken }
        };

        try
        {
            var response = await _httpClient.PostAsync(
                logoutEndpoint,
                new FormUrlEncodedContent(requestBody)
            );

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Logout failed with status: {StatusCode}", response.StatusCode);
                return false;
            }

            _logger.LogInformation("User logged out successfully");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during logout");
            return false;
        }
    }

    public async Task<string> GetAdminTokenAsync()
    {
        var tokenEndpoint = $"{BaseUrl}/realms/{Realm}/protocol/openid-connect/token";

        var requestBody = new Dictionary<string, string>
        {
            { "grant_type", "client_credentials" },
            { "client_id", ClientId },
            { "client_secret", ClientSecret }
        };

        try
        {
            var response = await _httpClient.PostAsync(
                tokenEndpoint,
                new FormUrlEncodedContent(requestBody)
            );

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Failed to get admin token");
                return null;
            }

            var content = await response.Content.ReadAsStringAsync();
            var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(content);
            return tokenResponse?.AccessToken;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting admin token");
            return null;
        }
    }

    public async Task<bool> RegisterAsync(RegisterRequest request)
    {
        try
        {
            // Lấy admin token
            var adminToken = await GetAdminTokenAsync();
            if (string.IsNullOrEmpty(adminToken))
            {
                _logger.LogError("Cannot obtain admin token for user registration");
                return false;
            }

            // Tạo payload cho Keycloak
            var userCreateRequest = new KeycloakUserCreateRequest
            {
                Username = request.Username,
                Email = request.Email,
                FirstName = request.FirstName,
                LastName = request.LastName,
                Enabled = true,
                EmailVerified = false,
                Credentials = new List<KeycloakCredential>
                {
                    new KeycloakCredential
                    {
                        Type = "password",
                        Value = request.Password,
                        Temporary = false
                    }
                }
            };

            // Gọi Admin API
            var createUserEndpoint = $"{BaseUrl}/admin/realms/{Realm}/users";

            var httpRequest = new HttpRequestMessage(HttpMethod.Post, createUserEndpoint);
            httpRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", adminToken);
            httpRequest.Content = new StringContent(
                JsonSerializer.Serialize(userCreateRequest),
                System.Text.Encoding.UTF8,
                "application/json"
            );

            var response = await _httpClient.SendAsync(httpRequest);

            if (response.StatusCode == System.Net.HttpStatusCode.Conflict)
            {
                _logger.LogWarning("User already exists: {Username}", request.Username);
                return false;
            }

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                _logger.LogError("User creation failed: {Error}", errorContent);
                return false;
            }

            _logger.LogInformation("User registered successfully: {Username}", request.Username);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during user registration");
            return false;
        }
    }
}
```

### C. Controller xử lý API

```csharp
// Controllers/AuthController.cs
[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IKeycloakService _keycloakService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        IKeycloakService keycloakService,
        ILogger<AuthController> logger)
    {
        _keycloakService = keycloakService;
        _logger = logger;
    }

    [HttpPost("login")]
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        try
        {
            var tokenResponse = await _keycloakService.LoginAsync(
                request.Username,
                request.Password
            );

            if (tokenResponse == null)
            {
                return Unauthorized(new { message = "Invalid username or password" });
            }

            return Ok(tokenResponse);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Login error");
            return StatusCode(500, new { message = "Internal server error" });
        }
    }

    [HttpPost("refresh")]
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        try
        {
            var tokenResponse = await _keycloakService.RefreshTokenAsync(
                request.RefreshToken
            );

            if (tokenResponse == null)
            {
                return Unauthorized(new { message = "Invalid or expired refresh token" });
            }

            return Ok(tokenResponse);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token refresh error");
            return StatusCode(500, new { message = "Internal server error" });
        }
    }

    [HttpPost("logout")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Logout([FromBody] LogoutRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        try
        {
            var success = await _keycloakService.LogoutAsync(request.RefreshToken);

            if (!success)
            {
                return StatusCode(500, new { message = "Logout failed" });
            }

            return Ok(new { message = "Logged out successfully" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Logout error");
            return StatusCode(500, new { message = "Internal server error" });
        }
    }

    [HttpPost("register")]
    [ProducesResponseType(StatusCodes.Status201Created)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status409Conflict)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Register([FromBody] RegisterRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        try
        {
            var success = await _keycloakService.RegisterAsync(request);

            if (!success)
            {
                return Conflict(new { message = "User already exists or registration failed" });
            }

            return StatusCode(201, new
            {
                message = "User registered successfully",
                username = request.Username
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Registration error");
            return StatusCode(500, new { message = "Internal server error" });
        }
    }
}
```

### D. Middleware xác thực JWT

```csharp
// Middleware/JwtValidationMiddleware.cs
public class JwtValidationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<JwtValidationMiddleware> _logger;

    public JwtValidationMiddleware(
        RequestDelegate next,
        ILogger<JwtValidationMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(
        HttpContext context,
        IKeycloakService keycloakService)
    {
        // Bỏ qua các endpoint không cần xác thực
        var path = context.Request.Path.Value;
        if (path.Contains("/api/auth/login") ||
            path.Contains("/api/auth/refresh") ||
            path.Contains("/api/auth/register"))
        {
            await _next(context);
            return;
        }

        // Lấy token từ Authorization header
        var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();

        if (string.IsNullOrEmpty(authHeader) ||
            !authHeader.StartsWith("Bearer "))
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsJsonAsync(
                new { message = "Missing or invalid authorization header" }
            );
            return;
        }

        var token = authHeader.Substring("Bearer ".Length).Trim();

        // Validate token
        var isValid = await keycloakService.ValidateTokenAsync(token);

        if (!isValid)
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsJsonAsync(
                new { message = "Invalid or expired token" }
            );
            return;
        }

        await _next(context);
    }
}
```

### E. Đăng ký Services trong Program.cs

```csharp
// Program.cs
var builder = WebApplication.CreateBuilder(args);

// Đăng ký HttpClient cho KeycloakService
builder.Services.AddHttpClient<IKeycloakService, KeycloakService>();

// Đăng ký Controllers
builder.Services.AddControllers();

// Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Sử dụng middleware xác thực JWT
app.UseMiddleware<JwtValidationMiddleware>();

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

app.Run();
```

### F. Phân quyền với Roles và Claims

#### 1. Tạo Attribute để kiểm tra Role

```csharp
// Attributes/RequireRoleAttribute.cs
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public class RequireRoleAttribute : Attribute, IAuthorizationFilter
{
    private readonly string[] _roles;

    public RequireRoleAttribute(params string[] roles)
    {
        _roles = roles;
    }

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var user = context.HttpContext.User;

        if (user == null || !user.Identity.IsAuthenticated)
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        // Kiểm tra user có ít nhất một role được yêu cầu
        var hasRole = _roles.Any(role =>
            user.Claims.Any(c => c.Type == "realm_access" && c.Value.Contains(role))
        );

        if (!hasRole)
        {
            context.Result = new ForbidResult();
        }
    }
}
```

#### 2. Middleware phân tích JWT Claims

```csharp
// Middleware/JwtClaimsMiddleware.cs
public class JwtClaimsMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<JwtClaimsMiddleware> _logger;

    public JwtClaimsMiddleware(
        RequestDelegate next,
        ILogger<JwtClaimsMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();

        if (!string.IsNullOrEmpty(authHeader) && authHeader.StartsWith("Bearer "))
        {
            var token = authHeader.Substring("Bearer ".Length).Trim();

            try
            {
                // Parse JWT token (không verify, chỉ đọc claims)
                var handler = new JsonWebTokenHandler();
                var jsonToken = handler.ReadJsonWebToken(token);

                // Tạo ClaimsIdentity từ token
                var claims = new List<Claim>();

                // Thêm basic claims
                claims.Add(new Claim(ClaimTypes.NameIdentifier, jsonToken.Subject ?? ""));
                claims.Add(new Claim(ClaimTypes.Name,
                    jsonToken.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value ?? ""));
                claims.Add(new Claim(ClaimTypes.Email,
                    jsonToken.Claims.FirstOrDefault(c => c.Type == "email")?.Value ?? ""));

                // Thêm Realm Roles
                var realmAccessClaim = jsonToken.Claims.FirstOrDefault(c => c.Type == "realm_access");
                if (realmAccessClaim != null)
                {
                    var realmAccess = JsonSerializer.Deserialize<JsonElement>(realmAccessClaim.Value);
                    if (realmAccess.TryGetProperty("roles", out var rolesElement))
                    {
                        foreach (var role in rolesElement.EnumerateArray())
                        {
                            claims.Add(new Claim(ClaimTypes.Role, role.GetString()));
                        }
                    }
                }

                // Thêm Resource Roles (Client roles)
                var resourceAccessClaim = jsonToken.Claims.FirstOrDefault(c => c.Type == "resource_access");
                if (resourceAccessClaim != null)
                {
                    claims.Add(new Claim("resource_access", resourceAccessClaim.Value));
                }

                var identity = new ClaimsIdentity(claims, "Keycloak");
                context.User = new ClaimsPrincipal(identity);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error parsing JWT claims");
            }
        }

        await _next(context);
    }
}
```

#### 3. Sử dụng trong Controller

```csharp
// Controllers/AdminController.cs
[ApiController]
[Route("api/[controller]")]
public class AdminController : ControllerBase
{
    private readonly ILogger<AdminController> _logger;

    public AdminController(ILogger<AdminController> logger)
    {
        _logger = logger;
    }

    // Chỉ admin mới truy cập được
    [HttpGet("dashboard")]
    [RequireRole("admin")]
    public IActionResult GetAdminDashboard()
    {
        var username = User.FindFirst(ClaimTypes.Name)?.Value;
        var roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value);

        return Ok(new
        {
            message = "Welcome to admin dashboard",
            user = username,
            roles = roles
        });
    }

    // Admin hoặc Moderator
    [HttpGet("users")]
    [RequireRole("admin", "moderator")]
    public IActionResult GetUsers()
    {
        return Ok(new { message = "List of users" });
    }

    // Public endpoint - không cần role
    [HttpGet("public")]
    public IActionResult GetPublicInfo()
    {
        return Ok(new { message = "Public information" });
    }
}
```

#### 4. Cập nhật Program.cs để đăng ký middleware

```csharp
// Program.cs
var builder = WebApplication.CreateBuilder(args);

// Đăng ký HttpClient cho KeycloakService
builder.Services.AddHttpClient<IKeycloakService, KeycloakService>();

// Đăng ký Controllers
builder.Services.AddControllers();

// Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// QUAN TRỌNG: Thứ tự middleware
app.UseHttpsRedirection();

// 1. Xác thực JWT (validate token)
app.UseMiddleware<JwtValidationMiddleware>();

// 2. Parse claims từ JWT
app.UseMiddleware<JwtClaimsMiddleware>();

// 3. Authorization
app.UseAuthorization();

app.MapControllers();

app.Run();
```

#### 5. Cấu hình Roles trong Keycloak

**Tạo Realm Roles:**
1. Vào Keycloak Admin Console
2. Chọn Realm của bạn
3. Vào **Roles** → **Realm Roles**
4. Click **Create Role**
5. Tạo các roles: `admin`, `user`, `moderator`, etc.

**Gán Roles cho User:**
1. Vào **Users** → Chọn user
2. Tab **Role Mappings**
3. Trong **Realm Roles**, assign các roles cần thiết

**Tạo Client Roles (Optional):**
1. Vào **Clients** → Chọn client của bạn
2. Tab **Roles**
3. Create role cụ thể cho client này
4. Assign cho users qua **Users** → **Role Mappings** → **Client Roles**

#### 6. Kiểm tra Roles trong JWT Token

Sau khi login, JWT token sẽ chứa roles trong payload:

```json
{
  "sub": "user-id-123",
  "preferred_username": "john.doe",
  "email": "john@example.com",
  "realm_access": {
    "roles": ["admin", "user"]
  },
  "resource_access": {
    "backend-service": {
      "roles": ["api-user"]
    }
  }
}
```

---

## 7. BẢO MẬT VÀ BEST PRACTICES

### A. Lưu trữ Token ở Client

#### Web Application (Browser):
- **Access Token**: Lưu trong memory (JavaScript variable) hoặc sessionStorage
- **Refresh Token**:
  - Option 1: HttpOnly Cookie (khuyến nghị)
  - Option 2: Secure localStorage với mã hóa
- **KHÔNG bao giờ**: Lưu token trong localStorage dạng plain text

#### Mobile Application:
- Sử dụng Secure Storage của platform:
  - iOS: Keychain
  - Android: EncryptedSharedPreferences
  - React Native: react-native-keychain

### B. Rate Limiting

Áp dụng rate limiting cho endpoint login để chống brute-force:

```csharp
// Services/RateLimitService.cs
public class LoginRateLimitAttribute : ActionFilterAttribute
{
    private static readonly Dictionary<string, LoginAttempt> _attempts = new();
    private const int MaxAttempts = 5;
    private static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    public override void OnActionExecuting(ActionExecutingContext context)
    {
        var ipAddress = context.HttpContext.Connection.RemoteIpAddress?.ToString();

        if (string.IsNullOrEmpty(ipAddress))
        {
            return;
        }

        lock (_attempts)
        {
            if (_attempts.TryGetValue(ipAddress, out var attempt))
            {
                if (attempt.IsLockedOut)
                {
                    context.Result = new StatusCodeResult(429); // Too Many Requests
                    return;
                }

                attempt.Count++;
                attempt.LastAttempt = DateTime.UtcNow;

                if (attempt.Count >= MaxAttempts)
                {
                    attempt.LockedUntil = DateTime.UtcNow.Add(LockoutDuration);
                }
            }
            else
            {
                _attempts[ipAddress] = new LoginAttempt
                {
                    Count = 1,
                    LastAttempt = DateTime.UtcNow
                };
            }
        }
    }

    public override void OnActionExecuted(ActionExecutedContext context)
    {
        // Reset đếm nếu login thành công
        if (context.Result is OkObjectResult)
        {
            var ipAddress = context.HttpContext.Connection.RemoteIpAddress?.ToString();
            if (!string.IsNullOrEmpty(ipAddress))
            {
                lock (_attempts)
                {
                    _attempts.Remove(ipAddress);
                }
            }
        }
    }
}

public class LoginAttempt
{
    public int Count { get; set; }
    public DateTime LastAttempt { get; set; }
    public DateTime? LockedUntil { get; set; }

    public bool IsLockedOut =>
        LockedUntil.HasValue && DateTime.UtcNow < LockedUntil.Value;
}

// Sử dụng trong Controller:
[HttpPost("login")]
[LoginRateLimit]
public async Task<IActionResult> Login([FromBody] LoginRequest request)
{
    // ...
}
```

### C. Xử lý lỗi chi tiết

```csharp
// Models/ErrorResponse.cs
public class ErrorResponse
{
    public string Message { get; set; }
    public string ErrorCode { get; set; }
    public Dictionary<string, string[]> ValidationErrors { get; set; }
}

// Middleware/ErrorHandlingMiddleware.cs
public class ErrorHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ErrorHandlingMiddleware> _logger;

    public ErrorHandlingMiddleware(
        RequestDelegate next,
        ILogger<ErrorHandlingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled exception");
            await HandleExceptionAsync(context, ex);
        }
    }

    private static Task HandleExceptionAsync(HttpContext context, Exception exception)
    {
        var errorResponse = new ErrorResponse
        {
            Message = "An error occurred processing your request",
            ErrorCode = "INTERNAL_ERROR"
        };

        context.Response.ContentType = "application/json";
        context.Response.StatusCode = 500;

        return context.Response.WriteAsJsonAsync(errorResponse);
    }
}
```

### D. HTTPS và CORS

```csharp
// Program.cs - Cấu hình CORS và HTTPS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy.WithOrigins("https://yourdomain.com")
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials(); // Nếu dùng HttpOnly Cookie
    });
});

// Force HTTPS
builder.Services.AddHsts(options =>
{
    options.MaxAge = TimeSpan.FromDays(365);
    options.IncludeSubDomains = true;
});

var app = builder.Build();

app.UseHsts();
app.UseHttpsRedirection();
app.UseCors("AllowFrontend");
```

### E. Token Validation Best Practices

```csharp
// Services/JwtValidationService.cs
public class JwtValidationService
{
    private readonly IConfiguration _configuration;
    private readonly ILogger<JwtValidationService> _logger;
    private JsonWebKeySet _jwks;
    private DateTime _jwksLastFetch = DateTime.MinValue;
    private static readonly TimeSpan JwksCacheDuration = TimeSpan.FromHours(24);

    public async Task<bool> ValidateTokenOfflineAsync(string token)
    {
        try
        {
            // Refresh JWKS nếu cần
            if (DateTime.UtcNow - _jwksLastFetch > JwksCacheDuration)
            {
                await RefreshJwksAsync();
            }

            var tokenHandler = new JsonWebTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = $"{_configuration["KEYCLOAK_BASE_URL"]}/realms/{_configuration["KEYCLOAK_REALM"]}",

                ValidateAudience = true,
                ValidAudience = _configuration["KEYCLOAK_CLIENT_ID"],

                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(5),

                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = _jwks.GetSigningKeys()
            };

            var result = await tokenHandler.ValidateTokenAsync(token, validationParameters);
            return result.IsValid;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Token validation failed");
            return false;
        }
    }

    private async Task RefreshJwksAsync()
    {
        var certsEndpoint = $"{_configuration["KEYCLOAK_BASE_URL"]}/realms/{_configuration["KEYCLOAK_REALM"]}/protocol/openid-connect/certs";

        using var httpClient = new HttpClient();
        var response = await httpClient.GetStringAsync(certsEndpoint);
        _jwks = new JsonWebKeySet(response);
        _jwksLastFetch = DateTime.UtcNow;
    }
}
```

---

## 8. TESTING

### A. Unit Tests cho KeycloakService

```csharp
// Tests/KeycloakServiceTests.cs
public class KeycloakServiceTests
{
    private readonly Mock<HttpMessageHandler> _httpMessageHandlerMock;
    private readonly Mock<IConfiguration> _configurationMock;
    private readonly Mock<ILogger<KeycloakService>> _loggerMock;
    private readonly KeycloakService _service;

    public KeycloakServiceTests()
    {
        _httpMessageHandlerMock = new Mock<HttpMessageHandler>();
        _configurationMock = new Mock<IConfiguration>();
        _loggerMock = new Mock<ILogger<KeycloakService>>();

        _configurationMock.Setup(c => c["KEYCLOAK_BASE_URL"]).Returns("https://auth.test.com");
        _configurationMock.Setup(c => c["KEYCLOAK_REALM"]).Returns("test-realm");
        _configurationMock.Setup(c => c["KEYCLOAK_CLIENT_ID"]).Returns("test-client");
        _configurationMock.Setup(c => c["KEYCLOAK_CLIENT_SECRET"]).Returns("test-secret");

        var httpClient = new HttpClient(_httpMessageHandlerMock.Object);
        _service = new KeycloakService(httpClient, _configurationMock.Object, _loggerMock.Object);
    }

    [Fact]
    public async Task LoginAsync_ValidCredentials_ReturnsTokenResponse()
    {
        // Arrange
        var mockResponse = new TokenResponse
        {
            AccessToken = "access_token_123",
            RefreshToken = "refresh_token_123",
            ExpiresIn = 300
        };

        _httpMessageHandlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>()
            )
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(JsonSerializer.Serialize(mockResponse))
            });

        // Act
        var result = await _service.LoginAsync("testuser", "testpass");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("access_token_123", result.AccessToken);
    }

    [Fact]
    public async Task LoginAsync_InvalidCredentials_ReturnsNull()
    {
        // Arrange
        _httpMessageHandlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>()
            )
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.Unauthorized,
                Content = new StringContent("{\"error\":\"invalid_grant\"}")
            });

        // Act
        var result = await _service.LoginAsync("baduser", "badpass");

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task RefreshTokenAsync_ValidToken_ReturnsNewTokens()
    {
        // Arrange
        var mockResponse = new TokenResponse
        {
            AccessToken = "new_access_token",
            RefreshToken = "new_refresh_token",
            ExpiresIn = 300
        };

        _httpMessageHandlerMock.Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>()
            )
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent(JsonSerializer.Serialize(mockResponse))
            });

        // Act
        var result = await _service.RefreshTokenAsync("valid_refresh_token");

        // Assert
        Assert.NotNull(result);
        Assert.Equal("new_access_token", result.AccessToken);
    }
}
```

### B. Integration Tests

```csharp
// Tests/AuthControllerIntegrationTests.cs
public class AuthControllerIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client;

    public AuthControllerIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task Login_ValidRequest_ReturnsOkWithTokens()
    {
        // Arrange
        var loginRequest = new LoginRequest
        {
            Username = "testuser",
            Password = "testpass"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);

        // Assert
        response.EnsureSuccessStatusCode();
        var tokenResponse = await response.Content.ReadFromJsonAsync<TokenResponse>();
        Assert.NotNull(tokenResponse);
        Assert.NotEmpty(tokenResponse.AccessToken);
    }

    [Fact]
    public async Task Login_InvalidRequest_ReturnsBadRequest()
    {
        // Arrange
        var loginRequest = new LoginRequest
        {
            Username = "", // Invalid
            Password = "testpass"
        };

        // Act
        var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }
}
```

### C. Postman Collection - Test Backend API

Collection này dùng để test các endpoint của Backend API:

```json
{
  "info": {
    "name": "Backend Authentication API",
    "description": "Test Backend endpoints that proxy to Keycloak",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Backend - Login",
      "event": [
        {
          "listen": "test",
          "script": {
            "exec": [
              "if (pm.response.code === 200) {",
              "    var jsonData = pm.response.json();",
              "    pm.environment.set(\"access_token\", jsonData.access_token);",
              "    pm.environment.set(\"refresh_token\", jsonData.refresh_token);",
              "    pm.environment.set(\"id_token\", jsonData.id_token);",
              "    console.log(\"Tokens saved to environment\");",
              "}"
            ]
          }
        }
      ],
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "Content-Type",
            "value": "application/json"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\n  \"username\": \"{{test_username}}\",\n  \"password\": \"{{test_password}}\"\n}"
        },
        "url": {
          "raw": "{{backend_url}}/api/auth/login",
          "host": ["{{backend_url}}"],
          "path": ["api", "auth", "login"]
        }
      },
      "response": []
    },
    {
      "name": "Backend - Refresh Token",
      "event": [
        {
          "listen": "test",
          "script": {
            "exec": [
              "if (pm.response.code === 200) {",
              "    var jsonData = pm.response.json();",
              "    pm.environment.set(\"access_token\", jsonData.access_token);",
              "    pm.environment.set(\"refresh_token\", jsonData.refresh_token);",
              "    console.log(\"New tokens saved to environment\");",
              "}"
            ]
          }
        }
      ],
      "request": {
        "method": "POST",
        "header": [
          {
            "key": "Content-Type",
            "value": "application/json"
          }
        ],
        "body": {
          "mode": "raw",
          "raw": "{\n  \"refreshToken\": \"{{refresh_token}}\"\n}"
        },
        "url": {
          "raw": "{{backend_url}}/api/auth/refresh",
          "host": ["{{backend_url}}"],
          "path": ["api", "auth", "refresh"]
        }
      },
      "response": []
    },
    {
      "name": "Backend - Protected Resource",
      "request": {
        "method": "GET",
        "header": [
          {
            "key": "Authorization",
            "value": "Bearer {{access_token}}"
          }
        ],
        "url": {
          "raw": "{{backend_url}}/api/protected-resource",
          "host": ["{{backend_url}}"],
          "path": ["api", "protected-resource"]
        }
      },
      "response": []
    }
  ],
  "variable": [
    {
      "key": "backend_url",
      "value": "https://localhost:5001"
    },
    {
      "key": "test_username",
      "value": "testuser"
    },
    {
      "key": "test_password",
      "value": "testpass"
    }
  ]
}
```

### D. Postman Collection - Test Keycloak Direct

Collection này dùng để test trực tiếp với Keycloak endpoints (bypass Backend):

```json
{
  "info": {
    "name": "Keycloak Direct API",
    "description": "Test Keycloak endpoints directly without Backend",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Keycloak Configuration",
      "item": [
        {
          "name": "Get OpenID Configuration",
          "request": {
            "method": "GET",
            "header": [],
            "url": {
              "raw": "{{keycloak_url}}/realms/{{realm}}/.well-known/openid-configuration",
              "host": ["{{keycloak_url}}"],
              "path": ["realms", "{{realm}}", ".well-known", "openid-configuration"]
            }
          },
          "response": []
        },
        {
          "name": "Get Public Keys (JWKS)",
          "request": {
            "method": "GET",
            "header": [],
            "url": {
              "raw": "{{keycloak_url}}/realms/{{realm}}/protocol/openid-connect/certs",
              "host": ["{{keycloak_url}}"],
              "path": ["realms", "{{realm}}", "protocol", "openid-connect", "certs"]
            }
          },
          "response": []
        }
      ]
    },
    {
      "name": "Token Operations",
      "item": [
        {
          "name": "Login (Password Grant)",
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "if (pm.response.code === 200) {",
                  "    var jsonData = pm.response.json();",
                  "    pm.environment.set(\"kc_access_token\", jsonData.access_token);",
                  "    pm.environment.set(\"kc_refresh_token\", jsonData.refresh_token);",
                  "    pm.environment.set(\"kc_id_token\", jsonData.id_token);",
                  "    ",
                  "    // Decode và log thông tin token",
                  "    var base64Url = jsonData.access_token.split('.')[1];",
                  "    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');",
                  "    var payload = JSON.parse(atob(base64));",
                  "    ",
                  "    console.log('Token expires at:', new Date(payload.exp * 1000));",
                  "    console.log('User:', payload.preferred_username);",
                  "    console.log('Roles:', payload.realm_access.roles);",
                  "}"
                ]
              }
            }
          ],
          "request": {
            "method": "POST",
            "header": [
              {
                "key": "Content-Type",
                "value": "application/x-www-form-urlencoded"
              }
            ],
            "body": {
              "mode": "urlencoded",
              "urlencoded": [
                {
                  "key": "grant_type",
                  "value": "password",
                  "type": "text"
                },
                {
                  "key": "client_id",
                  "value": "{{client_id}}",
                  "type": "text"
                },
                {
                  "key": "client_secret",
                  "value": "{{client_secret}}",
                  "type": "text"
                },
                {
                  "key": "username",
                  "value": "{{test_username}}",
                  "type": "text"
                },
                {
                  "key": "password",
                  "value": "{{test_password}}",
                  "type": "text"
                },
                {
                  "key": "scope",
                  "value": "openid profile email",
                  "type": "text"
                }
              ]
            },
            "url": {
              "raw": "{{keycloak_url}}/realms/{{realm}}/protocol/openid-connect/token",
              "host": ["{{keycloak_url}}"],
              "path": ["realms", "{{realm}}", "protocol", "openid-connect", "token"]
            }
          },
          "response": []
        },
        {
          "name": "Refresh Token",
          "event": [
            {
              "listen": "test",
              "script": {
                "exec": [
                  "if (pm.response.code === 200) {",
                  "    var jsonData = pm.response.json();",
                  "    pm.environment.set(\"kc_access_token\", jsonData.access_token);",
                  "    pm.environment.set(\"kc_refresh_token\", jsonData.refresh_token);",
                  "    console.log('Tokens refreshed successfully');",
                  "}"
                ]
              }
            }
          ],
          "request": {
            "method": "POST",
            "header": [
              {
                "key": "Content-Type",
                "value": "application/x-www-form-urlencoded"
              }
            ],
            "body": {
              "mode": "urlencoded",
              "urlencoded": [
                {
                  "key": "grant_type",
                  "value": "refresh_token",
                  "type": "text"
                },
                {
                  "key": "client_id",
                  "value": "{{client_id}}",
                  "type": "text"
                },
                {
                  "key": "client_secret",
                  "value": "{{client_secret}}",
                  "type": "text"
                },
                {
                  "key": "refresh_token",
                  "value": "{{kc_refresh_token}}",
                  "type": "text"
                }
              ]
            },
            "url": {
              "raw": "{{keycloak_url}}/realms/{{realm}}/protocol/openid-connect/token",
              "host": ["{{keycloak_url}}"],
              "path": ["realms", "{{realm}}", "protocol", "openid-connect", "token"]
            }
          },
          "response": []
        },
        {
          "name": "Token Introspection",
          "request": {
            "method": "POST",
            "header": [
              {
                "key": "Content-Type",
                "value": "application/x-www-form-urlencoded"
              }
            ],
            "body": {
              "mode": "urlencoded",
              "urlencoded": [
                {
                  "key": "token",
                  "value": "{{kc_access_token}}",
                  "type": "text"
                },
                {
                  "key": "client_id",
                  "value": "{{client_id}}",
                  "type": "text"
                },
                {
                  "key": "client_secret",
                  "value": "{{client_secret}}",
                  "type": "text"
                }
              ]
            },
            "url": {
              "raw": "{{keycloak_url}}/realms/{{realm}}/protocol/openid-connect/token/introspect",
              "host": ["{{keycloak_url}}"],
              "path": ["realms", "{{realm}}", "protocol", "openid-connect", "token", "introspect"]
            }
          },
          "response": []
        },
        {
          "name": "Revoke Token",
          "request": {
            "method": "POST",
            "header": [
              {
                "key": "Content-Type",
                "value": "application/x-www-form-urlencoded"
              }
            ],
            "body": {
              "mode": "urlencoded",
              "urlencoded": [
                {
                  "key": "token",
                  "value": "{{kc_refresh_token}}",
                  "type": "text"
                },
                {
                  "key": "client_id",
                  "value": "{{client_id}}",
                  "type": "text"
                },
                {
                  "key": "client_secret",
                  "value": "{{client_secret}}",
                  "type": "text"
                }
              ]
            },
            "url": {
              "raw": "{{keycloak_url}}/realms/{{realm}}/protocol/openid-connect/revoke",
              "host": ["{{keycloak_url}}"],
              "path": ["realms", "{{realm}}", "protocol", "openid-connect", "revoke"]
            }
          },
          "response": []
        }
      ]
    },
    {
      "name": "User Operations",
      "item": [
        {
          "name": "Get User Info",
          "request": {
            "method": "GET",
            "header": [
              {
                "key": "Authorization",
                "value": "Bearer {{kc_access_token}}"
              }
            ],
            "url": {
              "raw": "{{keycloak_url}}/realms/{{realm}}/protocol/openid-connect/userinfo",
              "host": ["{{keycloak_url}}"],
              "path": ["realms", "{{realm}}", "protocol", "openid-connect", "userinfo"]
            }
          },
          "response": []
        },
        {
          "name": "Logout",
          "request": {
            "method": "POST",
            "header": [
              {
                "key": "Content-Type",
                "value": "application/x-www-form-urlencoded"
              }
            ],
            "body": {
              "mode": "urlencoded",
              "urlencoded": [
                {
                  "key": "client_id",
                  "value": "{{client_id}}",
                  "type": "text"
                },
                {
                  "key": "client_secret",
                  "value": "{{client_secret}}",
                  "type": "text"
                },
                {
                  "key": "refresh_token",
                  "value": "{{kc_refresh_token}}",
                  "type": "text"
                }
              ]
            },
            "url": {
              "raw": "{{keycloak_url}}/realms/{{realm}}/protocol/openid-connect/logout",
              "host": ["{{keycloak_url}}"],
              "path": ["realms", "{{realm}}", "protocol", "openid-connect", "logout"]
            }
          },
          "response": []
        }
      ]
    }
  ],
  "variable": [
    {
      "key": "keycloak_url",
      "value": "https://auth.example.com"
    },
    {
      "key": "realm",
      "value": "my-project-realm"
    },
    {
      "key": "client_id",
      "value": "backend-service"
    },
    {
      "key": "client_secret",
      "value": "your-client-secret-here"
    },
    {
      "key": "test_username",
      "value": "testuser"
    },
    {
      "key": "test_password",
      "value": "testpass"
    }
  ]
}
```

### E. Hướng dẫn sử dụng Postman Collections

#### 1. Import Collections vào Postman

1. Mở Postman
2. Click **Import** ở góc trên bên trái
3. Copy/paste nội dung JSON của collection
4. Click **Import**

#### 2. Cấu hình Environment Variables

Tạo Environment mới trong Postman với các biến sau:

**Cho Backend API Collection:**
```
backend_url = https://localhost:5001
test_username = testuser
test_password = Test@123
access_token = (auto-filled by tests)
refresh_token = (auto-filled by tests)
```

**Cho Keycloak Direct Collection:**
```
keycloak_url = https://auth.example.com
realm = my-project-realm
client_id = backend-service
client_secret = xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
test_username = testuser
test_password = Test@123
kc_access_token = (auto-filled by tests)
kc_refresh_token = (auto-filled by tests)
kc_id_token = (auto-filled by tests)
```

#### 3. Test Flow

**Test Backend API:**
1. Run "Backend - Login" → Tokens tự động lưu vào environment
2. Run "Backend - Protected Resource" → Sử dụng access_token tự động
3. Run "Backend - Refresh Token" → Cập nhật tokens mới

**Test Keycloak Direct:**
1. Run "Get OpenID Configuration" → Verify Keycloak đang chạy
2. Run "Login (Password Grant)" → Lấy tokens từ Keycloak
3. Run "Get User Info" → Test access token
4. Run "Token Introspection" → Kiểm tra token validity
5. Run "Refresh Token" → Làm mới access token
6. Run "Logout" → Kết thúc session

#### 4. Scripts tự động trong Postman

Các request có **Test Scripts** để:
- Tự động lưu tokens vào environment variables
- Parse và log thông tin từ JWT token
- Validate response status codes
- Log user information và expiration time

#### 5. Tips

- Sử dụng **Postman Console** (View → Show Postman Console) để xem logs chi tiết
- Token sẽ tự động được lưu và sử dụng cho các request tiếp theo
- Có thể decode JWT token tại https://jwt.io để xem payload
- Kiểm tra expiration time trong Console để biết khi nào cần refresh

---

## 9. TROUBLESHOOTING

### Các lỗi thường gặp:

#### A. 401 Unauthorized khi login
**Nguyên nhân:**
- Sai username/password
- Client không được cấu hình đúng trong Keycloak
- Direct Access Grants chưa được enable

**Giải pháp:**
1. Kiểm tra credentials trong Keycloak Admin Console
2. Verify Client settings: Access Type = confidential, Direct Access Grants = ON
3. Kiểm tra Client Secret

#### B. Token validation failed
**Nguyên nhân:**
- Token đã hết hạn
- Sai public key
- Issuer/Audience không khớp

**Giải pháp:**
1. Kiểm tra thời gian hệ thống (clock skew)
2. Verify issuer URL khớp với Keycloak realm
3. Refresh JWKS cache

#### C. CORS errors
**Nguyên nhân:**
- Backend chưa cấu hình CORS
- Frontend domain không được whitelist

**Giải pháp:**
1. Thêm CORS policy trong Program.cs
2. Whitelist frontend domain
3. Đảm bảo credentials được phép nếu dùng cookies