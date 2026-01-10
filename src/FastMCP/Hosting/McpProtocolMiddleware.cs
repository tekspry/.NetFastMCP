using FastMCP.Attributes;
using FastMCP.Protocol;
using FastMCP.Server;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization; 
using Microsoft.Extensions.DependencyInjection;
using System.Security.Claims;

namespace FastMCP.Hosting;

public class McpProtocolMiddleware
{
    private readonly RequestDelegate _next;    
    private static readonly JsonSerializerOptions _jsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    
    // AuthorizationService is now used by the Handler, not the Middleware directly
    public McpProtocolMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, FastMCPServer server, McpRequestHandler requestHandler)
    {
        try
        {
            if (!IsValidMcpRequest(context))
            {
                await _next(context);
                return;
            }
            
            context.Response.ContentType = "application/json";

            var request = await ParseJsonRpcRequestAsync(context);
            if (request == null) return; 

            // The Core Transformation: Delegate to the Handler
            var response = await requestHandler.HandleRequestAsync(request, server, context.User);
            await JsonSerializer.SerializeAsync(context.Response.Body, response, _jsonOptions);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Middleware] UNHANDLED EXCEPTION: {ex}");
            await SendErrorResponseAsync(context, JsonRpcError.ErrorCodes.InternalError, "Internal server error", null);
        }
    }

    private bool IsValidMcpRequest(HttpContext context)
    {
        // Only process MCP requests to /mcp endpoint
        if (context.Request.Path != "/mcp" || !HttpMethods.IsPost(context.Request.Method))
        {
            return false;
        }
        return true;
    }

    private async Task<JsonRpcRequest?> ParseJsonRpcRequestAsync(HttpContext context)
    {
        try
        {
            var request = await JsonSerializer.DeserializeAsync<JsonRpcRequest>(context.Request.Body, _jsonOptions);
            Console.WriteLine($"[Middleware] Deserialized request: method={request?.Method}");

            if (request is null || request.JsonRpc != "2.0" || string.IsNullOrEmpty(request.Method))
            {
                Console.WriteLine("[Middleware] Invalid request format");
                await SendErrorResponseAsync(context, JsonRpcError.ErrorCodes.InvalidRequest, "Invalid JSON-RPC request.", request?.Id);
                return null;
            }

            return request;
        }
        catch (JsonException ex)
        {
            Console.WriteLine($"[Middleware] JSON parse error: {ex.Message}");
            await SendErrorResponseAsync(context, JsonRpcError.ErrorCodes.ParseError, $"JSON parse error: {ex.Message}", null);
            return null;
        }
    }

    private async Task SendErrorResponseAsync(HttpContext context, int code, string message, object? id)
    {
        var response = JsonRpcResponse.FromError(code, message, id);
        await JsonSerializer.SerializeAsync(context.Response.Body, response, _jsonOptions);
    }
}

public static class McpServerExtensions
{
    public static IApplicationBuilder UseMcpProtocol(this IApplicationBuilder app)
    {
        return app.UseMiddleware<McpProtocolMiddleware>();
    }
}
