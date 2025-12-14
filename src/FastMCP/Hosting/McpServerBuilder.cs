using FastMCP.Attributes;
using FastMCP.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System.Reflection;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using FastMCP.Authentication.Proxy;  // For OAuthProxy
using FastMCP.Authentication.Core;   // For ITokenVerifier

namespace FastMCP.Hosting;

/// <summary>
/// A builder for creating and configuring a FastMCP server application.
/// This follows the modern .NET hosting pattern (e.g., WebApplicationBuilder).
/// </summary>
public class McpServerBuilder
{
    private readonly WebApplicationBuilder _webAppBuilder;
    private readonly FastMCPServer _mcpServer;
    private string? _defaultChallengeScheme;  

    private McpServerBuilder(FastMCPServer mcpServer, string[]? args)
    {
        _mcpServer = mcpServer;
        _webAppBuilder = WebApplication.CreateBuilder(args ?? Array.Empty<string>());
        _webAppBuilder.Services.AddSingleton(_mcpServer);

        // --- Core Authentication and Authorization Setup ---
        // Adds authentication services with a default cookie scheme for session management.
        _webAppBuilder.Services.AddAuthentication(options =>
        {
            options.DefaultScheme = McpAuthenticationConstants.ApplicationScheme;
            options.DefaultChallengeScheme = McpAuthenticationConstants.ChallengeScheme; // Default challenge for unauthenticated access
        })
        .AddCookie(McpAuthenticationConstants.ApplicationScheme); // Configures cookie authentication

        // Adds authorization services. Policies will be configured via WithAuthorization.
        _webAppBuilder.Services.AddAuthorization();
        // --- End Core Authentication and Authorization Setup ---

         _webAppBuilder.Services.AddCors(options =>
         {
            options.AddPolicy("OAuthPolicy", policy =>
            {
                policy
                .AllowAnyOrigin()
                .AllowAnyMethod()
                .AllowAnyHeader()
                .WithExposedHeaders("WWW-Authenticate", "XOAuth-Scopes");        
            });            

         });

         var app = _webAppBuilder.Build();

        // Apply CORS policy to OAuth endpoints
        app.UseCors("OAuthPolicy");
    }

    /// <summary>
    /// Creates a new instance of the McpServerBuilder.
    /// </summary>
    public static McpServerBuilder Create(FastMCPServer server, string[]? args = null)
    {
        return new McpServerBuilder(server, args);
    }

    /// <summary>
    /// Scans the specified assembly for methods decorated with McpTool and McpResource 
    /// attributes and registers them with the server.
    /// </summary>
    public McpServerBuilder WithComponentsFrom(Assembly assembly)
    {
        var methods = assembly.GetTypes().SelectMany(t => t.GetMethods());

        foreach (var method in methods)
        {
            if (method.GetCustomAttribute<McpToolAttribute>() is not null)
            {
                _mcpServer.Tools.Add(method);
            }

            if (method.GetCustomAttribute<McpResourceAttribute>() is not null)
            {
                _mcpServer.Resources.Add(method);
            }
        }
        
        return this;
    }

    /// <summary>
    /// Allows direct configuration of the internal AuthenticationBuilder for advanced scenarios
    /// or adding custom authentication schemes.
    /// </summary>
    /// <param name="configure">An action to configure the <see cref="AuthenticationBuilder"/>.</param>
    public McpServerBuilder WithAuthentication(Action<AuthenticationBuilder> configure)
    {
        // AddAuthentication() returns the builder itself, so we call it to get the instance
        // then invoke the configure action.
        configure(_webAppBuilder.Services.AddAuthentication());
        return this;
    }

     /// <summary>
    /// Sets the default challenge scheme for authentication.
    /// This is typically called automatically when token verifiers are registered.
    /// </summary>
    /// <param name="schemeName">The authentication scheme name to use as default challenge.</param>
    public McpServerBuilder WithDefaultChallengeScheme(string schemeName)
    {
        if (string.IsNullOrEmpty(schemeName))
            throw new ArgumentException("Scheme name cannot be null or empty", nameof(schemeName));

        _defaultChallengeScheme = schemeName;
        
        // Update the authentication options
        _webAppBuilder.Services.Configure<AuthenticationOptions>(options =>
        {
            options.DefaultChallengeScheme = schemeName;
        });

        return this;
    }

    /// <summary>
    /// Allows configuration of authorization policies for the MCP server.
    /// </summary>
    /// <param name="configure">An action to configure the <see cref="AuthorizationOptions"/>.</param>
    public McpServerBuilder WithAuthorization(Action<AuthorizationOptions> configure)
    {
        _webAppBuilder.Services.AddAuthorization(configure);
        return this;
    }

    /// <summary>
    /// Builds the WebApplication that will host the MCP server.
    /// </summary>
    public WebApplication Build()
    {
        var app = _webAppBuilder.Build();

        // CRITICAL: Authentication must run before authorization
        // This ensures bearer tokens are authenticated before the MCP middleware checks authorization
        app.UseAuthentication();
        app.UseAuthorization();

        // Register OAuth Proxy endpoints if configured
        var oauthProxy = app.Services.GetService<OAuthProxy>();
        if (oauthProxy != null)
        {
            app.MapOAuthProxyEndpoints(oauthProxy);
        }

        // Register the MCP protocol middleware for /mcp endpoints
        app.UseMcpProtocol();

         // Register MCP OAuth discovery endpoints
        // Try to get the token verifier from DI if available
        var tokenVerifier = app.Services.GetService<ITokenVerifier>();
        app.MapMcpAuthEndpoints(
            mcpPath: "/mcp",
            baseUrl: null, // Will be determined from request
            tokenVerifier: tokenVerifier);

        // Root endpoint returns server metadata
        app.MapGet("/", () => 
            $"MCP Server '{_mcpServer.Name}' is running.\n" +
            $"Registered Tools: {_mcpServer.Tools.Count}\n" +
            $"Registered Resources: {_mcpServer.Resources.Count}");

        return app;
    }

    /// <summary>
    /// Configures OAuth Proxy for providers that don't support DCR.
    /// </summary>
    public McpServerBuilder WithOAuthProxy(
        OAuthProxyOptions options,
        ITokenVerifier tokenVerifier,
        IClientStore? clientStore = null)
    {
        var proxy = new OAuthProxy(options, tokenVerifier, clientStore);
        
        // Register the proxy as a service
        _webAppBuilder.Services.AddSingleton(proxy);
        
        // Map OAuth endpoints in Build method
        // (We'll handle this in the Build method)
        
        return this;
    }

     // Internal helper to expose the WebApplicationBuilder for extension methods (e.g., in McpAuthenticationExtensions)
    internal WebApplicationBuilder GetWebAppBuilder()
    {
        return _webAppBuilder;
    }
}
