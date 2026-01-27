namespace Keycloak.Net.Models;

/// <summary>
/// Represents the context of an authenticated Keycloak user.
/// </summary>
/// <typeparam name="TKey"></typeparam>
public class KeycloakUserContext<TKey>
{
    /// <summary>
    /// Gets or sets the unique identifier of the user.
    /// </summary>
    public TKey Id { get; set; }  = default!;

    /// <summary>
    /// Gets or sets the username of the user.
    /// </summary>
    public string UserName { get; set; } = null!;

    /// <summary>
    /// Gets or sets the email of the user.
    /// </summary>
    public string Email { get; set; } = null!;

    /// <summary>
    /// Gets or sets the roles assigned to the user.
    /// </summary>
    public List<string> Roles { get; set; } = null!;

    /// <summary>
    /// Gets or sets custom claims associated with the user.
    /// </summary>
    public Dictionary<string, string> CustomClaims { get; set; } = [];
}