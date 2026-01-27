namespace Keycloak.Net.Models;

/// <summary>
/// Configuration options for Keycloak integration.
/// </summary>
public class KeycloakOptions
{
    /// <summary>
    /// The authority URL of the Keycloak server.
    /// </summary>
    public string Authority { get; set; } = string.Empty;

    /// <summary>
    /// The audience for which the token is intended.
    /// </summary>
    public string Audience { get; set; } = string.Empty;

    /// <summary>
    /// The valid audiences for the token.
    /// </summary>
    public IEnumerable<string>? ValidAudiences { get; set; }

    /// <summary>
    /// The client ID registered in Keycloak.
    /// </summary>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Indicates whether HTTPS is required for metadata retrieval.
    /// </summary>
    public bool RequireHttpsMetadata { get; set; } = false;

    /// <summary>
    /// The metadata address for the Keycloak server.
    /// </summary>
    public string MetadataAddress => $"{Authority.TrimEnd('/')}/.well-known/openid-configuration";
}