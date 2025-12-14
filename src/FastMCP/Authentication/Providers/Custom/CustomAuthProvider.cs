using FastMCP.Authentication.Core;
using Microsoft.Extensions.Logging;

namespace FastMCP.Authentication.Providers.Custom;

/// <summary>
/// Base class for creating custom authentication providers.
/// Developers can inherit from this class to implement their own token verification logic.
/// </summary>
public abstract class CustomAuthProvider : IMcpAuthProvider
{
    protected readonly ILogger? Logger;
    protected readonly string? BaseUrl;
    protected readonly IReadOnlyList<string> RequiredScopes;

    protected CustomAuthProvider(
        string? baseUrl = null,
        IReadOnlyList<string>? requiredScopes = null,
        ILogger? logger = null)
    {
        BaseUrl = baseUrl;
        RequiredScopes = requiredScopes ?? Array.Empty<string>();
        Logger = logger;
    }

    /// <summary>
    /// Gets the authentication scheme name for this provider.
    /// Override this to provide a custom scheme name.
    /// </summary>
    public virtual string SchemeName => GetType().Name;

    /// <summary>
    /// Verifies a bearer token and returns access information if valid.
    /// This is the main method that must be implemented by custom providers.
    /// </summary>
    public abstract Task<AccessToken?> VerifyTokenAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// List of OAuth scopes required for all tokens verified by this provider.
    /// </summary>
    IReadOnlyList<string> ITokenVerifier.RequiredScopes => RequiredScopes;
}