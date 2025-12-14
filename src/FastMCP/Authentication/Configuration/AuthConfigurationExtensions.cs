using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;

namespace FastMCP.Authentication.Configuration;

/// <summary>
/// Extension methods for loading authentication configuration from environment variables.
/// Follows the PythonFastMCP pattern: FASTMCP_SERVER_AUTH_* environment variables.
/// </summary>
public static class AuthConfigurationExtensions
{
    /// <summary>
    /// Adds authentication configuration from environment variables.
    /// Environment variables follow the pattern: FASTMCP_SERVER_AUTH_{PROVIDER}_{SETTING}
    /// </summary>
    /// <param name="configuration">The configuration builder.</param>
    /// <returns>The configuration builder for chaining.</returns>
    public static IConfigurationBuilder AddFastMcpAuthEnvironmentVariables(this IConfigurationBuilder configuration)
    {
        return configuration.AddEnvironmentVariables("FASTMCP_SERVER_AUTH_");
    }

    /// <summary>
    /// Binds authentication options from configuration with environment variable support.
    /// </summary>
    /// <typeparam name="TOptions">The options type.</typeparam>
    /// <param name="configuration">The configuration.</param>
    /// <param name="sectionName">The configuration section name (e.g., "Authentication:Google").</param>
    /// <returns>The bound options instance.</returns>
    public static TOptions GetAuthOptions<TOptions>(this IConfiguration configuration, string sectionName)
        where TOptions : class, new()
    {
        var options = new TOptions();
        configuration.GetSection(sectionName).Bind(options);
        
        // Also bind from environment variables with prefix
        var envPrefix = $"FASTMCP_SERVER_AUTH_{sectionName.Split(':').Last().ToUpperInvariant()}_";
        var envConfig = new ConfigurationBuilder()
            .AddEnvironmentVariables(envPrefix)
            .Build();
        
        envConfig.Bind(options);
        
        return options;
    }

    /// <summary>
    /// Parses a comma-separated or space-separated list of scopes from a string.
    /// </summary>
    public static IReadOnlyList<string> ParseScopes(string? scopeString)
    {
        if (string.IsNullOrWhiteSpace(scopeString))
            return Array.Empty<string>();

        return scopeString
            .Split(new[] { ',', ' ', ';' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim())
            .Where(s => !string.IsNullOrEmpty(s))
            .ToList();
    }
}