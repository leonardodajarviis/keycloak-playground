using System.Net.Http.Json;
using Keycloak.Net.Abstractions;
using Keycloak.Net.Exceptions;
using Keycloak.Net.Models;
using Microsoft.Extensions.Options;

namespace Keycloak.Net.Services;

/// <summary>
/// Service for interacting with Keycloak server for token introspection and health monitoring.
/// </summary>
public class KeycloakService : IKeycloakService
{
    private readonly HttpClient _httpClient;
    private readonly KeycloakOptions _options;
    private readonly string _introspectionEndpoint;

    /// <summary>
    /// Initializes a new instance of the <see cref="KeycloakService"/> class.
    /// </summary>
    /// <param name="httpClientFactory"></param>
    /// <param name="options"></param>
    public KeycloakService(IHttpClientFactory httpClientFactory, IOptions<KeycloakOptions> options)
    {
        _httpClient = httpClientFactory.CreateClient("KeycloakClient");
        _options = options.Value;

        ValidateConfiguration();

        // Construct OIDC introspection endpoint
        _introspectionEndpoint = $"{_options.Authority.TrimEnd('/')}/protocol/openid-connect/token/introspect";
    }

    /// <summary>
    /// Validates required options at startup.
    /// </summary>
    private void ValidateConfiguration()
    {
        if (string.IsNullOrWhiteSpace(_options.Authority))
            throw new KeycloakConfigurationException("Keycloak Authority is missing.", nameof(_options.Authority));

        if (string.IsNullOrWhiteSpace(_options.Audience))
            throw new KeycloakConfigurationException("Keycloak Audience (ClientId) is missing.", nameof(_options.Audience));

        if (string.IsNullOrWhiteSpace(_options.ClientSecret))
            throw new KeycloakConfigurationException("Keycloak ClientSecret is required for introspection.", nameof(_options.ClientSecret));
    }

    /// <inheritdoc />
    public async Task<Result<KeycloakIntrospectionResponse>> IntrospectTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return Result<KeycloakIntrospectionResponse>.Failure(
                KeycloakErrorCodes.InvalidToken,
                "Token cannot be null or empty.");
        }

        // Introspection requires x-www-form-urlencoded content
        var requestContent = new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("token", token),
            new KeyValuePair<string, string>("client_id", _options.Audience),
            new KeyValuePair<string, string>("client_secret", _options.ClientSecret)
        ]);

        try
        {
            var response = await _httpClient.PostAsync(_introspectionEndpoint, requestContent, cancellationToken);

            // Handle Client Authentication issues (Common cause for 403 Forbidden)
            if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized || 
                response.StatusCode == System.Net.HttpStatusCode.Forbidden)
            {
                return Result<KeycloakIntrospectionResponse>.Failure(
                    KeycloakErrorCodes.ClientAuthenticationFailed,
                    "Client authentication failed. Ensure ClientSecret is correct and Client is set to 'Confidential' in Keycloak.");
            }

            if (!response.IsSuccessStatusCode)
            {
                throw new KeycloakConnectionException(
                    $"Introspection failed with status code: {response.StatusCode}",
                    _introspectionEndpoint);
            }

            var introspectionResponse = await response.Content.ReadFromJsonAsync<KeycloakIntrospectionResponse>(cancellationToken);

            if (introspectionResponse == null)
            {
                throw new KeycloakConnectionException("Received empty response from Keycloak.", _introspectionEndpoint);
            }

            // If token is revoked, expired on server, or user is disabled
            if (!introspectionResponse.Active)
            {
                return Result<KeycloakIntrospectionResponse>.Failure(
                    KeycloakErrorCodes.TokenInactive,
                    "Token is no longer active or has been revoked.");
            }

            return Result<KeycloakIntrospectionResponse>.Success(introspectionResponse);
        }
        catch (HttpRequestException ex)
        {
            throw new KeycloakConnectionException(
                "Network error occurred while connecting to Keycloak introspection endpoint.",
                _introspectionEndpoint,
                ex);
        }
    }

    /// <inheritdoc />
    public async Task<bool> CheckHealthAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var metadataAddress = $"{_options.Authority.TrimEnd('/')}/.well-known/openid-configuration";
            var response = await _httpClient.GetAsync(metadataAddress, cancellationToken);
            
            return response.IsSuccessStatusCode;
        }
        catch
        {
            return false;
        }
    }
}