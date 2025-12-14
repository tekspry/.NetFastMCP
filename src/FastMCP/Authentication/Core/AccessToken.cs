using System;
using System.Collections.Generic;
using System.Linq;

namespace FastMCP.Authentication.Core;

/// <summary>
/// Represents a verified access token with its claims and metadata.
/// This is the result of successful token verification.
/// </summary>
public class AccessToken
{
    /// <summary>
    /// The raw token string.
    /// </summary>
    public string Token { get; set; } = string.Empty;

    /// <summary>
    /// The client ID that owns this token.
    /// </summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// List of OAuth scopes granted to this token.
    /// </summary>
    public IReadOnlyList<string> Scopes { get; set; } = Array.Empty<string>();

    /// <summary>
    /// Token expiration time as Unix timestamp (seconds since epoch).
    /// Null if the token doesn't expire.
    /// </summary>
    public long? ExpiresAt { get; set; }

    /// <summary>
    /// Additional claims extracted from the token.
    /// Common claims include: sub, email, name, etc.
    /// </summary>
    public IReadOnlyDictionary<string, object> Claims { get; set; } = new Dictionary<string, object>();

    /// <summary>
    /// Checks if the token is expired.
    /// </summary>
    public bool IsExpired
    {
        get
        {
            if (ExpiresAt == null)
                return false;
            
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            return ExpiresAt.Value <= now;
        }
    }

    /// <summary>
    /// Checks if the token has all required scopes.
    /// </summary>
    public bool HasRequiredScopes(IEnumerable<string> requiredScopes)
    {
        if (requiredScopes == null || !requiredScopes.Any())
            return true;

        var tokenScopes = new HashSet<string>(Scopes, StringComparer.OrdinalIgnoreCase);
        var required = new HashSet<string>(requiredScopes, StringComparer.OrdinalIgnoreCase);
        
        return required.IsSubsetOf(tokenScopes);
    }
}