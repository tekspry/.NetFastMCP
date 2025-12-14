using System;
using System.Collections.Generic;

namespace FastMCP.Authentication.Proxy;

/// <summary>
/// Represents a registered OAuth client for DCR.
/// </summary>
public class OAuthClientRegistration
{
    /// <summary>
    /// Client ID (generated or provided by client).
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Client secret (generated or provided by client).
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Allowed redirect URIs for this client.
    /// </summary>
    public IReadOnlyList<string> RedirectUris { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Grant types supported by this client.
    /// </summary>
    public IReadOnlyList<string> GrantTypes { get; set; } = new[] { "authorization_code", "refresh_token" };

    /// <summary>
    /// Scopes requested by this client.
    /// </summary>
    public string Scope { get; set; } = string.Empty;

    /// <summary>
    /// Token endpoint authentication method.
    /// </summary>
    public string TokenEndpointAuthMethod { get; set; } = "none";

    /// <summary>
    /// Client name (optional).
    /// </summary>
    public string? ClientName { get; set; }

    /// <summary>
    /// When this client was registered.
    /// </summary>
    public DateTime RegisteredAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Allowed redirect URI patterns for validation.
    /// </summary>
    public IReadOnlyList<string>? AllowedRedirectUriPatterns { get; set; }
}