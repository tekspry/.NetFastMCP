namespace FastMCP.Authentication.Core;

/// <summary>
/// Base interface for all FastMCP authentication providers.
/// This interface provides a unified interface for all authentication providers,
/// whether they are simple token verifiers or full OAuth authorization servers.
/// </summary>
public interface IMcpAuthProvider : ITokenVerifier
{
    /// <summary>
    /// The base URL of this server (e.g., http://localhost:8000).
    /// This is used for constructing .well-known endpoints and OAuth metadata.
    /// </summary>
    string? BaseUrl { get; }

    /// <summary>
    /// Gets the authentication scheme name for this provider.
    /// This is used when registering with ASP.NET Core authentication.
    /// </summary>
    string SchemeName { get; }
}