using System.Collections.Generic;

namespace FastMCP.Authentication.Configuration;

/// <summary>
/// Configuration options for Auth0 authentication.
/// </summary>
public class Auth0AuthOptions
{
    public string? ConfigUrl { get; set; }
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; }
    public string? Audience { get; set; }
    public IReadOnlyList<string>? RequiredScopes { get; set; } = new[] { "openid" };
}