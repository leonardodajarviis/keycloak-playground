using Keycloak.Net.Models;

namespace Keycloak.Net.Abstractions;

/// <summary>
/// Provides access to the current authenticated Keycloak user.
/// </summary>
/// <typeparam name="TUser"></typeparam>
/// <typeparam name="TUserKey"></typeparam>
public interface IKeycloakUserProvider<TUser, TUserKey> where TUser : KeycloakUserContext<TUserKey>
{
    /// <summary>
    /// Gets the current authenticated user.
    /// </summary>
    /// <returns></returns>
    TUser? GetCurrentUser();

    /// <summary>
    /// Indicates whether the current user is authenticated.
    /// </summary>
    bool IsAuthenticated { get; }
}

