using Keycloak.Net.Middlewares;
using Keycloak.Net.Models;
using Microsoft.AspNetCore.Builder;

namespace Keycloak.Net.Extensions;

/// <summary>
/// Extension methods for integrating Keycloak authentication middleware into an application pipeline.
/// </summary>
public static class ApplicationBuilderExtensions
{
    /// <summary>
    /// Adds Keycloak authentication middleware to the application pipeline.
    /// This middleware validates JWT tokens and optionally performs token introspection.
    /// Place this before UseAuthorization() to ensure HttpContext.User is set before authorization policies run.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <param name="configureOptions">Optional configuration for authentication behavior.</param>
    /// <returns>The application builder for chaining.</returns>
    public static IApplicationBuilder UseKeycloakAuth(
        this IApplicationBuilder app,
        Action<KeycloakAuthOptions>? configureOptions = null)
    {
        var options = new KeycloakAuthOptions();
        configureOptions?.Invoke(options);

        return app.UseMiddleware<KeycloakAuthMiddleware>(options);
    }
}