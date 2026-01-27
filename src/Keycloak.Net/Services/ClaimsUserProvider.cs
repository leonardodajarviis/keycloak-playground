using System.Security.Claims;
using Keycloak.Net.Abstractions;
using Keycloak.Net.Models;
using Microsoft.AspNetCore.Http;

namespace Keycloak.Net.Services;

/// <summary>
/// Provides the current authenticated Keycloak user by mapping claims from the HttpContext.
/// </summary>
/// <typeparam name="TUser"></typeparam>
/// <typeparam name="TUserKey"></typeparam>
public class ClaimsUserProvider<TUser, TUserKey> : IKeycloakUserProvider<TUser, TUserKey> 
    where TUser : KeycloakUserContext<TUserKey>, new()
{
    /// <summary>
    /// The HTTP context accessor to retrieve the current HttpContext.
    /// </summary>
    protected readonly IHttpContextAccessor Accessor;

    /// <summary>
    /// Initializes a new instance of the <see cref="ClaimsUserProvider{TUser, TUserKey}"/> class.
    /// </summary>
    /// <param name="accessor"></param>
    public ClaimsUserProvider(IHttpContextAccessor accessor)
    {
        Accessor = accessor;
    }

    /// <summary>
    /// Indicates whether the current user is authenticated.
    /// </summary>
    public bool IsAuthenticated => Accessor.HttpContext?.User?.Identity?.IsAuthenticated ?? false;

    /// <summary>
    /// Gets the current authenticated user.
    /// </summary>
    /// <returns></returns>
    public TUser? GetCurrentUser()
    {
        var principal = Accessor.HttpContext?.User;
        if (principal == null || !IsAuthenticated) return null;

        // Extract ID first to ensure we can create the context
        var idClaim = principal.FindFirst(ClaimTypes.NameIdentifier);
        if (idClaim == null) return null;

        return MapClaimsToUser(principal, idClaim.Value);
    }

    /// <summary>
    /// This method is virtual so other projects can override the mapping logic.
    /// </summary>
    protected virtual TUser MapClaimsToUser(ClaimsPrincipal principal, string idValue)
    {
        return new TUser
        {
            Id = (TUserKey)Convert.ChangeType(idValue, typeof(TUserKey)),
            UserName = principal.FindFirst("preferred_username")?.Value ?? "<unknown>",
            Email = principal.FindFirst(ClaimTypes.Email)?.Value ?? "<unknown>",
            Roles = [.. principal.FindAll(ClaimTypes.Role).Select(c => c.Value)]
        };
    }
}