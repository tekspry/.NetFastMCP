using FastMCP.Attributes;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace GoogleOAuthServer.Tools;  // Change namespace per provider

public static class Tools
{
    [McpTool]
    [Authorize]
    public static string Echo(string message)
    {
        return $"Echo: {message}";
    }

    [McpTool]
    [Authorize]
    public static Dictionary<string, string> GetUserInfo(ClaimsPrincipal user)
    {
        return new Dictionary<string, string>
        {
            { "Name", user.Identity?.Name ?? "Unknown" },
            { "IsAuthenticated", user.Identity?.IsAuthenticated.ToString() ?? "False" },
            { "AuthenticationType", user.Identity?.AuthenticationType ?? "None" },
            { "Claims", string.Join(", ", user.Claims.Select(c => $"{c.Type}={c.Value}")) }
        };
    }

    // Optional: Provider-specific claim examples
    [McpTool]
    [Authorize]
    public static Dictionary<string, string> GetProviderSpecificInfo(ClaimsPrincipal user)
    {
        var info = new Dictionary<string, string>();
        
        // These claims vary by provider, but the code structure is the same
        info["Email"] = user.FindFirst(ClaimTypes.Email)?.Value ?? 
                       user.FindFirst("email")?.Value ?? 
                       user.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")?.Value ?? 
                       "Not available";
        
        info["Subject"] = user.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? 
                         user.FindFirst("sub")?.Value ?? 
                         "Not available";
        
        // Provider-specific claims (examples)
        // Google: "picture", "locale"
        // GitHub: "avatar_url", "login"
        // Azure AD: "oid", "tid"
        // Auth0: "sub", "email_verified"
        // Okta: "sub", "preferred_username"
        
        return info;
    }

    [McpTool]
    public static string PublicEcho(string message)
    {
        return $"Public Echo: {message}";
    }
}