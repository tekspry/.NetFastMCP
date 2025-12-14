using System.Collections.Generic;

namespace FastMCP.Authentication.Configuration;

/// <summary>
/// Configuration options for Azure AD authentication.
/// </summary>
public class AzureAdAuthOptions
{
    public string? TenantId { get; set; }
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; }
    public IReadOnlyList<string>? RequiredScopes { get; set; }
    public string BaseAuthority { get; set; } = "login.microsoftonline.com";
}