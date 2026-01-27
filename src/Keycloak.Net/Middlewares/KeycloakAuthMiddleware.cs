using System.Security.Claims;
using Keycloak.Net.Abstractions;
using Keycloak.Net.Exceptions;
using Keycloak.Net.Models;
using Microsoft.AspNetCore.Http;

namespace Keycloak.Net.Middlewares;

/// <summary>
/// Middleware responsible for secondary token validation (Introspection).
/// It runs after the standard JwtBearer authentication to ensure the token 
/// is still active/fresh on the Keycloak server.
/// </summary>
public class KeycloakAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly KeycloakAuthOptions _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="KeycloakAuthMiddleware"/> class.
    /// </summary>
    /// <param name="next"></param>
    /// <param name="options"></param>
    public KeycloakAuthMiddleware(RequestDelegate next, KeycloakAuthOptions options)
    {
        _next = next;
        _options = options;
    }

    /// <summary>
    /// Processes an HTTP request to perform token introspection if enabled.
    /// </summary>
    /// <param name="context"></param>
    /// <param name="keycloakService"></param>
    /// <returns></returns>
    public async Task InvokeAsync(HttpContext context, IKeycloakService keycloakService)
    {
        // Only perform introspection if the user was already successfully authenticated by JwtBearer
        if (context.User.Identity?.IsAuthenticated == true)
        {
            if (_options.EnableIntrospection)
            {
                var token = ExtractBearerToken(context);

                // If token cannot be extracted but user is authenticated, continue to next middleware
                if (string.IsNullOrEmpty(token))
                {
                    await _next(context);
                    return;
                }

                try
                {
                    // Check token status directly with Keycloak server
                    var introspectionResult = await keycloakService.IntrospectTokenAsync(token, context.RequestAborted);

                    if (!introspectionResult.IsSuccess)
                    {
                        // Token is revoked or user is disabled. Clear the identity.
                        context.User = new ClaimsPrincipal(new ClaimsIdentity());

                        await HandleAuthenticationFailureAsync(context, new AuthenticationFailureContext
                        {
                            ErrorCode = introspectionResult.ErrorCode ?? "TOKEN_REVOKED",
                            ErrorMessage = introspectionResult.ErrorMessage ?? "Token is no longer active.",
                            Token = token
                        });
                        return;
                    }
                }
                catch (KeycloakException ex)
                {
                    // Handle server-side or network failures (e.g., Keycloak is down)
                    await HandleInfrastructureFailureAsync(context, new InfrastructureFailureContext
                    {
                        Exception = ex,
                        ErrorCode = "AUTH_SERVICE_UNAVAILABLE",
                        ErrorMessage = "Authentication service is temporarily unavailable."
                    });
                    return;
                }
            }
        }

        // Authentication passed or introspection is disabled, proceed to next middleware
        await _next(context);
    }

    /// <summary>
    /// Extracts the raw JWT string from the Authorization header.
    /// </summary>
    private static string? ExtractBearerToken(HttpContext context)
    {
        var authHeader = context.Request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }
        return authHeader["Bearer ".Length..].Trim();
    }

    private async Task HandleAuthenticationFailureAsync(HttpContext context, AuthenticationFailureContext failureContext)
    {
        if (_options.OnAuthenticationFailed != null)
        {
            await _options.OnAuthenticationFailed(context, failureContext);
        }
        else
        {
            await DefaultAuthenticationFailureHandler(context, failureContext);
        }
    }

    private async Task HandleInfrastructureFailureAsync(HttpContext context, InfrastructureFailureContext failureContext)
    {
        if (_options.OnInfrastructureFailed != null)
        {
            await _options.OnInfrastructureFailed(context, failureContext);
        }
        else
        {
            await DefaultInfrastructureFailureHandler(context, failureContext);
        }
    }

    private Task DefaultAuthenticationFailureHandler(HttpContext context, AuthenticationFailureContext failureContext)
    {
        var statusCode = _options.GetStatusCode(failureContext.ErrorCode);
        var message = _options.GetErrorMessage(failureContext.ErrorCode);

        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json";

        return context.Response.WriteAsJsonAsync(new
        {
            error = failureContext.ErrorCode,
            message = failureContext.ErrorMessage ?? message
        });
    }

    private static Task DefaultInfrastructureFailureHandler(HttpContext context, InfrastructureFailureContext failureContext)
    {
        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        context.Response.ContentType = "application/json";

        return context.Response.WriteAsJsonAsync(new
        {
            error = failureContext.ErrorCode,
            message = failureContext.ErrorMessage
        });
    }
}