using System.Collections.Generic;

namespace FastMCP.Authentication.Configuration;

/// <summary>
/// Configuration options for Google authentication.
/// </summary>
public class GoogleAuthOptions
{
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; }
    public IReadOnlyList<string>? RequiredScopes { get; set; }
    public int TimeoutSeconds { get; set; } = 10;
}