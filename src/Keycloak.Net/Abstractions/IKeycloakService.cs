using System.Security.Claims;
using Keycloak.Net.Models;

namespace Keycloak.Net.Abstractions;

/// <summary>
/// Defines methods for interacting with Keycloak services.
/// </summary>
public interface IKeycloakService
{
    /// <summary>
    /// Introspects a token via Keycloak's introspection endpoint.
    /// Returns a Result indicating success or failure with appropriate error codes.
    /// Authentication/token failures return Failure, not exceptions.
    /// Throws only for infrastructure failures (network issues, configuration errors).
    /// </summary>
    Task<Result<KeycloakIntrospectionResponse>> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks if the Keycloak server is reachable and operational.
    /// Returns true if the server is healthy and responds successfully.
    /// Returns false if the server is unreachable or returns an error.
    /// Does not throw exceptions - handles all errors gracefully.
    /// </summary>
    Task<bool> CheckHealthAsync(CancellationToken cancellationToken = default);
}