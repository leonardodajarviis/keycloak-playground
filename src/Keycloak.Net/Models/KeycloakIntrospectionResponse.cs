using System.Text.Json.Serialization;

namespace Keycloak.Net.Models;

/// <summary>
/// Represents the response from Keycloak's token introspection endpoint.
/// </summary>
public class KeycloakIntrospectionResponse
{
    /// <summary>
    /// Indicates whether the token is active.
    /// </summary>
    [JsonPropertyName("active")]
    public bool Active { get; set; } 

    /// <summary>
    /// Expiration time of the token (epoch time).
    /// </summary>
    [JsonPropertyName("exp")]
    public long Expiration { get; set; }

    /// <summary>
    /// Issued at time of the token (epoch time).
    /// </summary>
    [JsonPropertyName("iat")]
    public long IssuedAt { get; set; }

    /// <summary>
    /// Subject of the token.
    /// </summary>
    [JsonPropertyName("sub")]
    public string Subject { get; set; } = string.Empty;

    /// <summary>
    /// Username associated with the token.
    /// </summary>
    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Client ID associated with the token.
    /// </summary>
    [JsonPropertyName("client_id")]
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Realm access information, including roles.
    /// </summary>
    [JsonPropertyName("realm_access")]
    public KeycloakRealmAccess? RealmAccess { get; set; }

    /// <summary>
    /// Scope of the token.
    /// </summary>
    [JsonPropertyName("scope")]
    public string Scope { get; set; } = string.Empty;
}

/// <summary>
/// Represents the realm access information in the token introspection response.
/// </summary>
public class KeycloakRealmAccess
{
    /// <summary>
    /// Roles assigned to the user in the realm.
    /// </summary>
    [JsonPropertyName("roles")]
    public List<string> Roles { get; set; } = new();
}