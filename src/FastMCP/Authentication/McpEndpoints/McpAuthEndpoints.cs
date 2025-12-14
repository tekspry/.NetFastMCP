using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using FastMCP.Authentication.Core;
using FastMCP.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace FastMCP.Authentication.McpEndpoints;

/// <summary>
/// Provides MCP-specific OAuth endpoints for metadata discovery.
/// These endpoints allow MCP clients to discover authentication requirements automatically.
/// </summary>
public static class McpAuthEndpoints
{
    /// <summary>
    /// Registers MCP OAuth discovery endpoints.
    /// </summary>
    /// <param name="app">The web application.</param>
    /// <param name="mcpPath">The MCP endpoint path (e.g., "/mcp").</param>
    /// <param name="baseUrl">The base URL of the server.</param>
    /// <param name="tokenVerifier">Optional token verifier to get required scopes.</param>
    public static void MapMcpAuthEndpoints(
        this WebApplication app,
        string mcpPath = "/mcp",
        string? baseUrl = null,
        ITokenVerifier? tokenVerifier = null)
    {
        var logger = app.Services.GetRequiredService<ILogger<McpAuthEndpoints>>();
        
        // Get base URL from request if not provided
        baseUrl ??= app.Urls.FirstOrDefault() ?? "http://localhost:5000";

        // OAuth Authorization Server Metadata (RFC 8414)
        app.MapGet("/.well-known/oauth-authorization-server", async (HttpContext context) =>
        {
            var authMetadata = new
            {
                issuer = baseUrl,
                authorization_endpoint = $"{baseUrl}/oauth/authorize",
                token_endpoint = $"{baseUrl}/oauth/token",
                registration_endpoint = $"{baseUrl}/oauth/register",
                scopes_supported = tokenVerifier?.RequiredScopes ?? Array.Empty<string>(),
                response_types_supported = new[] { "code" },
                grant_types_supported = new[] { "authorization_code", "client_credentials" },
                token_endpoint_auth_methods_supported = new[] { "client_secret_basic", "client_secret_post" },
                code_challenge_methods_supported = new[] { "S256" }
            };

            context.Response.ContentType = "application/json";
            await JsonSerializer.SerializeAsync(context.Response.Body, authMetadata, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
        })
        .WithName("OAuthAuthorizationServerMetadata")
        .AllowAnonymous();

        // OpenID Connect Discovery (optional, for OIDC providers)
        app.MapGet("/.well-known/openid-configuration", async (HttpContext context) =>
        {
            var oidcMetadata = new
            {
                issuer = baseUrl,
                authorization_endpoint = $"{baseUrl}/oauth/authorize",
                token_endpoint = $"{baseUrl}/oauth/token",
                userinfo_endpoint = $"{baseUrl}/oauth/userinfo",
                jwks_uri = $"{baseUrl}/.well-known/jwks.json",
                scopes_supported = tokenVerifier?.RequiredScopes ?? Array.Empty<string>(),
                response_types_supported = new[] { "code" },
                grant_types_supported = new[] { "authorization_code" },
                subject_types_supported = new[] { "public" },
                id_token_signing_alg_values_supported = new[] { "RS256" }
            };

            context.Response.ContentType = "application/json";
            await JsonSerializer.SerializeAsync(context.Response.Body, oidcMetadata, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
        })
        .WithName("OpenIdConfiguration")
        .AllowAnonymous();

        // Protected Resource Metadata (MCP-specific)
        app.MapGet($"{mcpPath}/.well-known/protected-resource", async (HttpContext context, FastMCPServer server) =>
        {
            var scopes = tokenVerifier?.RequiredScopes ?? Array.Empty<string>();
            var baseUrl = context.Request.Scheme + "://" + context.Request.Host;
            
            // RFC 9728 compliant format
            var resourceMetadata = new
            {
                // Resource identifier (unique for this MCP server)
                resource = $"mcp://{context.Request.Host}/{mcpPath.TrimStart('/')}",
                
                // List of authorization servers that can authorize access
                authorization_servers = new object[]
                {
                    new 
                    { 
                        issuer = baseUrl,
                        metadata_uri = $"{baseUrl}/.well-known/oauth-authorization-server"
                    }
                },
                
                // Scopes supported by this resource
                scopes_supported = scopes.ToList(),
                
                // HTTP methods for accessing this resource
                access_methods = new[]
                {
                    new 
                    { 
                        method = "POST",
                        path = mcpPath,
                        bearer_token = true,
                        bearer_token_location = "header"
                    }
                }};

            context.Response.ContentType = "application/json";
            await JsonSerializer.SerializeAsync(context.Response.Body, resourceMetadata, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });
        })
        .WithName("ProtectedResourceMetadata")
        .AllowAnonymous();

        logger.LogInformation("MCP OAuth endpoints registered at /.well-known/oauth-authorization-server and {McpPath}/.well-known/protected-resource", mcpPath);
    }
}