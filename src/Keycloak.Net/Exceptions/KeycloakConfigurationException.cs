namespace Keycloak.Net.Exceptions;

/// <summary>
/// Exception thrown when Keycloak configuration is invalid or missing
/// </summary>
public class KeycloakConfigurationException : KeycloakException
{
    /// <summary>
    /// The configuration key that caused the exception, if applicable.
    /// </summary>
    public string? ConfigurationKey { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeycloakConfigurationException"/> class.
    /// </summary>
    public KeycloakConfigurationException()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeycloakConfigurationException"/> class with a specified error message.
    /// </summary>
    /// <param name="message"></param>
    public KeycloakConfigurationException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeycloakConfigurationException"/> class with a specified error message and configuration key.
    /// </summary>
    /// <param name="message"></param>
    /// <param name="configurationKey"></param>
    public KeycloakConfigurationException(string message, string configurationKey)
        : base(message)
    {
        ConfigurationKey = configurationKey;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeycloakConfigurationException"/> class with a specified error message and a reference to the inner exception that is the cause of this exception.
    /// </summary>
    /// <param name="message"></param>
    /// <param name="inner"></param>
    public KeycloakConfigurationException(string message, Exception inner)
        : base(message, inner)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeycloakConfigurationException"/> class with a specified error message, configuration key, and a reference to the inner exception that is the cause of this exception.
    /// </summary>
    /// <param name="message"></param>
    /// <param name="configurationKey"></param>
    /// <param name="inner"></param>
    public KeycloakConfigurationException(string message, string configurationKey, Exception inner)
        : base(message, inner)
    {
        ConfigurationKey = configurationKey;
    }
}
