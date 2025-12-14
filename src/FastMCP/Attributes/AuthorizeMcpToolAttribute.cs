using System;

namespace FastMCP.Attributes;

/// <summary>
/// Specifies that an MCP tool requires authorization.
/// This attribute can be used to apply policies, roles, or specific authentication schemes
/// to an MCP method, securing its invocation.
/// </summary>
[AttributeUsage(AttributeTargets.Method, Inherited = false, AllowMultiple = false)]
public sealed class AuthorizeMcpToolAttribute : Attribute
{
    /// <summary>
    /// Gets or sets the policy name that the current user must satisfy to access the MCP tool.
    /// Policies are configured in the <see cref="AuthorizationOptions"/>.
    /// </summary>
    public string? Policy { get; set; }

    /// <summary>
    /// Gets or sets the roles that the current user must be a member of to access the MCP tool.
    /// Multiple roles can be specified as a comma-separated string (e.g., "Admin,Manager").
    /// </summary>
    public string? Roles { get; set; }

    /// <summary>
    /// Gets or sets the authentication schemes that are challenged. If specified,
    /// the user must be authenticated by one of these schemes to access the tool.
    /// Multiple schemes can be specified as a comma-separated string.
    /// </summary>
    public string? AuthenticationSchemes { get; set; }
}