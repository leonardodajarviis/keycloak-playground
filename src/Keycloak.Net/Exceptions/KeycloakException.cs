namespace Keycloak.Net.Exceptions;

/// <summary>
/// Base exception class for Keycloak-related errors
/// </summary>
public class KeycloakException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="KeycloakException"/> class.
    /// </summary>
    public KeycloakException()
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeycloakException"/> class with a specified error message.
    /// </summary>
    /// <param name="message"></param>
    public KeycloakException(string message)
        : base(message)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="KeycloakException"/> class with a specified error message and a reference to the inner exception that is the cause of this exception.
    /// </summary>
    /// <param name="message"></param>
    /// <param name="inner"></param>
    public KeycloakException(string message, Exception inner)
        : base(message, inner)
    {
    }
}
