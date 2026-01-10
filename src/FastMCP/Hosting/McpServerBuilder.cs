using FastMCP.Attributes;
using FastMCP.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using System.Reflection;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using FastMCP.Authentication.Proxy;
using FastMCP.Authentication.Core;
using Microsoft.Extensions.Logging;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Cors.Infrastructure;
using FastMCP.Authentication.McpEndpoints;

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
        
        bool isStdioMode = args?.Contains("--stdio") ?? false;
        
        // ... (Registration code) ...
        // --- Logging Setup ---
        _webAppBuilder.Services.AddLogging(config =>
        {
            if (isStdioMode)
            {
                config.ClearProviders(); // Critical: Remove default Console logger added by CreateBuilder
            }
            else
            {
                // Only add Console logger if NOT in Stdio mode
                config.AddConsole();
            }
            
            config.SetMinimumLevel(LogLevel.Information);
            // ... filters ...
        });
        // --- End Logging Setup ---
        
        _webAppBuilder.Services.AddSingleton(_mcpServer);

         _webAppBuilder.Services.AddScoped<McpRequestHandler>();

          // NEW: Register Stdio Transport
        _webAppBuilder.Services.AddScoped<McpStdioTransport>();

        // --- Core Authentication and Authorization Setup ---
        _webAppBuilder.Services.AddAuthentication(options =>
        {
            // For APIs: Bearer token authentication via JWT Bearer scheme
            // For web: Fall back to cookie authentication for sign-in/sign-out
            // DefaultAuthenticateScheme determines which scheme is used to populate context.User
            // Since we're building an API (MCP), default to Bearer for token extraction
            options.DefaultAuthenticateScheme = "Bearer";  // Extract Bearer tokens first
            options.DefaultSignInScheme = McpAuthenticationConstants.ApplicationScheme;  // Use cookie for sign-in
            options.DefaultChallengeScheme = "Bearer";  // Default challenge to Bearer (401 responses)
        })
        .AddCookie(McpAuthenticationConstants.ApplicationScheme);

        _webAppBuilder.Services.AddAuthorization();
        // --- End Core Authentication and Authorization Setup ---

        // --- Rate Limiting Setup ---
        _webAppBuilder.Services.AddRateLimiter(rateLimiterOptions =>
        {
            rateLimiterOptions.AddFixedWindowLimiter("oauth-token", options =>
            {
                options.PermitLimit = 10;
                options.Window = TimeSpan.FromMinutes(1);
                options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
                options.QueueLimit = 2;
            });

            rateLimiterOptions.AddFixedWindowLimiter("oauth-register", options =>
            {
                options.PermitLimit = 5;
                options.Window = TimeSpan.FromHours(1);
                options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
                options.QueueLimit = 1;
            });

            rateLimiterOptions.AddFixedWindowLimiter("oauth-authorize", options =>
            {
                options.PermitLimit = 30;
                options.Window = TimeSpan.FromMinutes(1);
                options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
                options.QueueLimit = 5;
            });

            rateLimiterOptions.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        });
        // --- End Rate Limiting Setup ---

        // --- CORS Setup ---
        _webAppBuilder.Services.AddCors(options =>
        {
            options.AddPolicy("OAuthPolicy", policy =>
            {
                policy
                    .WithOrigins("http://localhost:*", "http://127.0.0.1:*")
                    .AllowAnyMethod()
                    .AllowAnyHeader()
                    .AllowCredentials()
                    .WithExposedHeaders("WWW-Authenticate", "X-OAuth-Scopes", "Location");
            });
        });
        // --- End CORS Setup ---


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

            if (method.GetCustomAttribute<McpPromptAttribute>() is not null)
            {
                _mcpServer.Prompts.Add(method);
            }
        }

        return this;
    }

    /// <summary>
    /// Allows direct configuration of the internal AuthenticationBuilder for advanced scenarios
    /// or adding custom authentication schemes.
    /// </summary>
    public McpServerBuilder WithAuthentication(Action<AuthenticationBuilder> configure)
    {
        configure(_webAppBuilder.Services.AddAuthentication());
        return this;
    }

    /// <summary>
    /// Sets the default challenge scheme for authentication.
    /// </summary>
    public McpServerBuilder WithDefaultChallengeScheme(string schemeName)
    {
        if (string.IsNullOrEmpty(schemeName))
            throw new ArgumentException("Scheme name cannot be null or empty", nameof(schemeName));

        _defaultChallengeScheme = schemeName;

        _webAppBuilder.Services.Configure<AuthenticationOptions>(options =>
        {
            options.DefaultChallengeScheme = schemeName;
        });

        return this;
    }

    /// <summary>
    /// Allows configuration of authorization policies for the MCP server.
    /// </summary>
    public McpServerBuilder WithAuthorization(Action<AuthorizationOptions> configure)
    {
        _webAppBuilder.Services.AddAuthorization(configure);
        return this;
    }

    /// <summary>
    /// Configures CORS policy for OAuth and MCP endpoints.
    /// </summary>
    public McpServerBuilder WithCorsPolicy(string[]? allowedOrigins = null, bool allowCredentials = true)
    {
        _webAppBuilder.Services.Configure<CorsOptions>(options =>
        {
            options.AddPolicy("OAuthPolicy", policy =>
            {
                if (allowedOrigins != null && allowedOrigins.Length > 0)
                {
                    policy.WithOrigins(allowedOrigins);
                }
                else
                {
                    policy.SetIsOriginAllowed(_ => true);  // For development only
                }

                policy
                    .AllowAnyMethod()
                    .AllowAnyHeader()
                    .WithExposedHeaders("WWW-Authenticate", "X-OAuth-Scopes", "Location");

                if (allowCredentials)
                {
                    policy.AllowCredentials();
                }
            });
        });

        return this;
    }

    /// <summary>
    /// Configures OAuth Proxy for providers that don't support DCR.
    /// </summary>
    public McpServerBuilder WithOAuthProxy(
        OAuthProxyOptions options,
        ITokenVerifier tokenVerifier,
        IClientStore? clientStore = null)
    {
        if (options == null)
            throw new ArgumentNullException(nameof(options));
        if (tokenVerifier == null)
            throw new ArgumentNullException(nameof(tokenVerifier));

        // Register OAuthProxyOptions
        _webAppBuilder.Services.AddSingleton(options);

        if (clientStore != null)
        {
            // If a clientStore is provided, register it.
            // This allows specific OAuth proxies to use their own client stores if needed.
            // If there's already an IClientStore registered, this will add another one,
            // which GetServices<IClientStore>() would correctly handle if multiple are needed.
            _webAppBuilder.Services.AddSingleton<IClientStore>(clientStore);
        }
        else if (!_webAppBuilder.Services.Any(x => x.ServiceType == typeof(IClientStore)))
        {
            // If no clientStore is provided and no IClientStore is already registered, add a default.
            _webAppBuilder.Services.AddSingleton<IClientStore>(new InMemoryClientStore());
        }

        // Set default challenge scheme to Bearer for OAuth
        WithDefaultChallengeScheme("Bearer");

        // Register the OAuthProxy service (it uses the provided tokenVerifier)
        // We will resolve IClientStore from the service provider when constructing OAuthProxy
        _webAppBuilder.Services.AddSingleton(provider => new OAuthProxy(
            options,
            tokenVerifier,
            provider.GetService<IClientStore>() ?? new InMemoryClientStore() // Resolve IClientStore from the provider
        ));

        return this;
    }

    /// <summary>
    /// Builds the WebApplication that will host the MCP server.
    /// </summary>
    public WebApplication Build()
    {
        var app = _webAppBuilder.Build();

        // Apply CORS middleware BEFORE authentication
        app.UseCors("OAuthPolicy");

        // Apply rate limiting middleware
        app.UseRateLimiter();

        // CRITICAL: Authentication must run before authorization
        app.UseAuthentication();
        
        // Custom middleware to explicitly extract and validate Bearer tokens
        // This ensures Bearer tokens are properly authenticated even without a DefaultScheme
        app.UseMiddleware<BearerAuthenticationMiddleware>();
        
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
        var tokenVerifier = app.Services.GetService<ITokenVerifier>();
        app.MapMcpAuthEndpoints(
            mcpPath: "/mcp",
            baseUrl: null,
            tokenVerifier: tokenVerifier);

        // Root endpoint returns server metadata
        app.MapGet("/", () =>
            $"MCP Server '{_mcpServer.Name}' is running.\n" +
            $"Registered Tools: {_mcpServer.Tools.Count}\n" +
            $"Registered Resources: {_mcpServer.Resources.Count}");

        return app;
    }



    // Internal helper to expose the WebApplicationBuilder for extension methods
    internal WebApplicationBuilder GetWebAppBuilder()
    {
        return _webAppBuilder;
    }
}