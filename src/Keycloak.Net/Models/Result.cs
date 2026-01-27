namespace Keycloak.Net.Models;

/// <summary>
/// Represents the outcome of an operation that can succeed or fail.
/// </summary>
/// <typeparam name="T">The type of the result value on success.</typeparam>
public class Result<T>
{
    /// <summary>
    /// Indicates whether the operation was successful.
    /// </summary>
    public bool IsSuccess { get; }

    /// <summary>
    /// The result value if the operation was successful; otherwise, null.
    /// </summary>
    public T? Value { get; }

    /// <summary>
    /// The error code if the operation failed; otherwise, null.
    /// </summary>
    public string? ErrorCode { get; }

    /// <summary>
    /// The error message if the operation failed; otherwise, null.
    /// </summary>
    public string? ErrorMessage { get; }

    private Result(bool isSuccess, T? value, string? errorCode, string? errorMessage)
    {
        IsSuccess = isSuccess;
        Value = value;
        ErrorCode = errorCode;
        ErrorMessage = errorMessage;
    }

    /// <summary>
    /// Creates a successful result with a value.
    /// </summary>
    public static Result<T> Success(T value) => new(true, value, null, null);

    /// <summary>
    /// Creates a failed result with an error code and optional message.
    /// </summary>
    public static Result<T> Failure(string errorCode, string? errorMessage = null) => 
        new(false, default, errorCode, errorMessage);
}

/// <summary>
/// Standard error codes for Keycloak operations.
/// </summary>
public static class KeycloakErrorCodes
{
    /// <summary>Token is invalid, expired, or malformed.</summary>
    public const string InvalidToken = "invalid_token";
    
    /// <summary>Token validation failed (signature, audience, issuer, etc).</summary>
    public const string TokenValidationFailed = "token_validation_failed";
    
    /// <summary>Token has expired (normal authentication flow).</summary>
    public const string TokenExpired = "token_expired";
    
    /// <summary>Token is not active according to introspection.</summary>
    public const string TokenInactive = "token_inactive";
    
    /// <summary>Client authentication failed (wrong credentials).</summary>
    public const string ClientAuthenticationFailed = "client_authentication_failed";
}
