using System.Collections.Generic;

namespace FastMCP.Authentication.Proxy;

/// <summary>
/// Configuration options for OAuth Proxy.
/// </summary>
public class OAuthProxyOptions
{
    /// <summary>
    /// Upstream authorization endpoint URL.
    /// </summary>
    public string UpstreamAuthorizationEndpoint { get; set; } = string.Empty;

    /// <summary>
    /// Upstream token endpoint URL.
    /// </summary>
    public string UpstreamTokenEndpoint { get; set; } = string.Empty;

    /// <summary>
    /// Upstream client ID (pre-registered with the upstream provider).
    /// </summary>
    public string UpstreamClientId { get; set; } = string.Empty;

    /// <summary>
    /// Upstream client secret (pre-registered with the upstream provider).
    /// </summary>
    public string UpstreamClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Optional upstream revocation endpoint URL.
    /// </summary>
    public string? UpstreamRevocationEndpoint { get; set; }

    /// <summary>
    /// Base URL of this FastMCP server.
    /// </summary>
    public string BaseUrl { get; set; } = string.Empty;

    /// <summary>
    /// Redirect path configured in upstream OAuth app (defaults to "/auth/callback").
    /// </summary>
    public string RedirectPath { get; set; } = "/auth/callback";

    /// <summary>
    /// Issuer URL for OAuth metadata (defaults to base_url).
    /// </summary>
    public string? IssuerUrl { get; set; }

    /// <summary>
    /// List of allowed redirect URI patterns for MCP clients.
    /// Patterns support wildcards (e.g., "http://localhost:*", "https://*.example.com/*").
    /// If null, only localhost redirect URIs are allowed.
    /// If empty list, all redirect URIs are allowed (not recommended for production).
    /// </summary>
    public IReadOnlyList<string>? AllowedClientRedirectUris { get; set; }

    /// <summary>
    /// Valid scopes that can be requested by clients.
    /// </summary>
    public IReadOnlyList<string>? ValidScopes { get; set; }

    /// <summary>
    /// Whether to forward PKCE to upstream server (default true).
    /// </summary>
    public bool ForwardPkce { get; set; } = true;

    /// <summary>
    /// Token endpoint authentication method for upstream server.
    /// Common values: "client_secret_basic", "client_secret_post", "none".
    /// </summary>
    public string? TokenEndpointAuthMethod { get; set; }

    /// <summary>
    /// Whether to require user consent before authorizing clients (default true).
    /// </summary>
    public bool RequireAuthorizationConsent { get; set; } = true;
}