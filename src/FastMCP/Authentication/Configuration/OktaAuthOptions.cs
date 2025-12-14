using System.Collections.Generic;

namespace FastMCP.Authentication.Configuration;

/// <summary>
/// Configuration options for Okta authentication.
/// </summary>
public class OktaAuthOptions
{
    public string? Domain { get; set; }
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; }
    public string? Audience { get; set; }
    public IReadOnlyList<string>? RequiredScopes { get; set; }
    public bool UseIntrospection { get; set; } = false;
    public int TimeoutSeconds { get; set; } = 10;
}