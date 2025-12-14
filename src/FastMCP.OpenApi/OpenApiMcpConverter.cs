using FastMCP.Attributes;
using FastMCP.Server;
using Microsoft.OpenApi.Models;
using Microsoft.OpenApi.Readers;
using System.Reflection;
using System.Text.Json;
using System.Net.Http;
using System.Linq;

namespace FastMCP.OpenApi;

/// <summary>
/// Converts OpenAPI operations into MCP tools and registers them with a FastMCPServer.
/// </summary>
public static class OpenApiMcpConverter
{
    private static readonly HttpClient _httpClient = new();

    /// <summary>
    /// Loads an OpenAPI document from a stream and converts its operations into MCP tools.
    /// </summary>
    /// <param name="stream">The stream containing the OpenAPI document.</param>
    /// <param name="server">The FastMCPServer instance to register components with.</param>
    /// <param name="baseUrl">Optional base URL for the OpenAPI service.</param>
    public static void RegisterFromOpenApi(Stream stream, FastMCPServer server, string? baseUrl = null)
    {
        var openApiDocument = new OpenApiStreamReader().Read(stream, out var diagnostic);

        if (diagnostic.Errors.Any())
        {
            throw new InvalidOperationException($"Failed to parse OpenAPI document: {string.Join("; ", diagnostic.Errors.Select(e => e.Message))}");
        }

        foreach (var path in openApiDocument.Paths)
        {
            foreach (var operationEntry in path.Value.Operations)
            {
                var httpMethod = operationEntry.Key.ToString().ToUpperInvariant();
                var operation = operationEntry.Value;

                var toolName = operation.OperationId ?? $"{httpMethod}_{path.Key.Replace("/", "_").Replace("{", "").Replace("}", "")}";
                var description = operation.Summary ?? operation.Description;

                // Create an OpenApiToolProxy instance for each operation
                var toolProxy = new OpenApiToolProxy(toolName, httpMethod, path.Key, operation, description, baseUrl);
                
                // Store the proxy in the server's dynamic tools dictionary
                server.DynamicTools[toolName] = toolProxy;
                
                // For discovery purposes, also add a dummy method to the Tools list
                // The McpProtocolMiddleware will need to check DynamicTools first before invoking
                var dummyMethod = CreateDummyToolMethod(toolName, description);
                server.Tools.Add(dummyMethod);
            }
        }
    }

    private static MethodInfo CreateDummyToolMethod(string toolName, string? description)
    {
        // Create a dummy static method that serves as a placeholder.
        // The real invocation will be handled by McpProtocolMiddleware
        // which will check the DynamicTools dictionary.
        var methodBuilder = typeof(OpenApiMcpConverter).GetMethod(nameof(DummyOpenApiTool), 
            BindingFlags.NonPublic | BindingFlags.Static);
        
        if (methodBuilder == null)
        {
            throw new InvalidOperationException("Could not find DummyOpenApiTool method.");
        }
        
        return methodBuilder;
    }

    // This is a placeholder static method that represents an OpenAPI tool.
    // The actual invocation is handled by McpProtocolMiddleware.
    [McpTool]
    private static object DummyOpenApiTool(string toolName, JsonElement parameters)
    {
        return new { status = "openapi_tool", message = $"Tool {toolName} invoked" };
    }
}

/// <summary>
/// Represents an OpenAPI operation that can be invoked as an MCP tool.
/// </summary>
// public class OpenApiToolProxy
// {
//     public string HttpMethod { get; }
//     public string Path { get; }
//     public OpenApiOperation Operation { get; }
//     public string? Description { get; }
//     public string? BaseUrl { get; }

//     public OpenApiToolProxy(string httpMethod, string path, OpenApiOperation operation, string? description, string? baseUrl = null)
//     {
//         HttpMethod = httpMethod;
//         Path = path;
//         Operation = operation;
//         Description = description;
//         BaseUrl = baseUrl;
//     }

//     /// <summary>
//     /// Executes the OpenAPI operation with the provided parameters.
//     /// </summary>
//     public async Task<object> ExecuteAsync(JsonElement parameters)
//     {
//         // Placeholder for actual HTTP request logic
//         // In a real implementation, this would:
//         // 1. Build the full URL from BaseUrl and Path
//         // 2. Serialize parameters to query string, headers, or request body
//         // 3. Send the request using HttpClient
//         // 4. Deserialize and return the response
        
//         await Task.Delay(10); // Simulate async work
//         return new 
//         { 
//             status = "success",
//             operation = $"{HttpMethod} {Path}",
//             receivedParams = parameters.GetRawText() 
//         };
//     }
// }
