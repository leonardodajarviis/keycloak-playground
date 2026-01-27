using Microsoft.AspNetCore.Http;

namespace Keycloak.Net.Models;

/// <summary>
/// Configuration options for Keycloak authentication middleware.
/// </summary>
public class KeycloakAuthOptions
{
    /// <summary>
    /// Whether to perform token introspection in addition to JWT validation.
    /// Default: false (JWT validation only).
    /// </summary>
    public bool EnableIntrospection { get; set; } = true;

    /// <summary>
    /// Custom error handler for authentication failures.
    /// If not provided, default JSON error responses will be used.
    /// </summary>
    public Func<HttpContext, AuthenticationFailureContext, Task>? OnAuthenticationFailed { get; set; }

    /// <summary>
    /// Custom error handler for infrastructure failures (connection errors, configuration errors).
    /// If not provided, default JSON error responses will be used.
    /// </summary>
    public Func<HttpContext, InfrastructureFailureContext, Task>? OnInfrastructureFailed { get; set; }

    /// <summary>
    /// Maps Keycloak error codes to HTTP status codes.
    /// Default mapping: all authentication errors return 401, client auth errors return 503.
    /// </summary>
    public Func<string, int> GetStatusCode { get; set; } = DefaultStatusCodeMapper;

    /// <summary>
    /// Maps Keycloak error codes to user-friendly error messages.
    /// </summary>
    public Func<string, string> GetErrorMessage { get; set; } = DefaultErrorMessageMapper;

    /// <summary>
    /// Default status code mapper.
    /// </summary>
    private static int DefaultStatusCodeMapper(string errorCode)
    {
        return errorCode switch
        {
            KeycloakErrorCodes.ClientAuthenticationFailed => StatusCodes.Status503ServiceUnavailable,
            _ => StatusCodes.Status401Unauthorized
        };
    }

    /// <summary>
    /// Default error message mapper.
    /// </summary>
    private static string DefaultErrorMessageMapper(string errorCode)
    {
        return errorCode switch
        {
            KeycloakErrorCodes.TokenInactive => "Token is not active.",
            KeycloakErrorCodes.TokenExpired => "Token has expired.",
            KeycloakErrorCodes.InvalidToken => "Token is invalid.",
            KeycloakErrorCodes.TokenValidationFailed => "Token validation failed.",
            KeycloakErrorCodes.ClientAuthenticationFailed => "Authentication service configuration error.",
            _ => "Authentication failed."
        };
    }
}

/// <summary>
/// Context for authentication failure events.
/// </summary>
public class AuthenticationFailureContext
{
    /// <summary>
    /// The error code from Keycloak (e.g., "invalid_token", "token_expired").
    /// </summary>
    public required string ErrorCode { get; init; }

    /// <summary>
    /// Optional error message providing more details.
    /// </summary>
    public string? ErrorMessage { get; init; }

    /// <summary>
    /// The token that failed authentication (may be null if no token was provided).
    /// </summary>
    public string? Token { get; init; }
}

/// <summary>
/// Context for infrastructure failure events.
/// </summary>
public class InfrastructureFailureContext
{
    /// <summary>
    /// The exception that caused the infrastructure failure.
    /// </summary>
    public required Exception Exception { get; init; }

    /// <summary>
    /// A descriptive error code (e.g., "SERVICE_UNAVAILABLE", "SERVICE_MISCONFIGURED").
    /// </summary>
    public required string ErrorCode { get; init; }

    /// <summary>
    /// User-friendly error message.
    /// </summary>
    public required string ErrorMessage { get; init; }
}
