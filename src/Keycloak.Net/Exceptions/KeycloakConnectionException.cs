namespace Keycloak.Net.Exceptions;

/// <summary>
/// Exception thrown when connection to Keycloak server fails
/// </summary>
public class KeycloakConnectionException : KeycloakException
{
    /// <summary>
    /// The Keycloak server URL that caused the exception, if applicable.
    /// </summary>
    public string? ServerUrl { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeycloakConnectionException"/> class.
    /// </summary>
    public KeycloakConnectionException()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeycloakConnectionException"/> class with a specified error message.
    /// </summary>
    /// <param name="message"></param>
    public KeycloakConnectionException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeycloakConnectionException"/> class with a specified error message and Keycloak server URL.
    /// </summary>
    /// <param name="message"></param>
    /// <param name="serverUrl"></param>
    public KeycloakConnectionException(string message, string serverUrl)
        : base(message)
    {
        ServerUrl = serverUrl;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeycloakConnectionException"/> class with a specified error message and a reference to the inner exception that is the cause of this exception.
    /// </summary>
    /// <param name="message"></param>
    /// <param name="inner"></param>
    public KeycloakConnectionException(string message, Exception inner)
        : base(message, inner)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeycloakConnectionException"/> class with a specified error message, Keycloak server URL, and a reference to the inner exception that is the cause of this exception.
    /// </summary>
    /// <param name="message"></param>
    /// <param name="serverUrl"></param>
    /// <param name="inner"></param>
    public KeycloakConnectionException(string message, string serverUrl, Exception inner)
        : base(message, inner)
    {
        ServerUrl = serverUrl;
    }
}
