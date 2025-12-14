using FastMCP.Server; // Added for IDynamicMcpToolHandler
using Microsoft.OpenApi.Models;
using System; 
using System.Reflection;
using System.Text.Json;
using System.Threading.Tasks;

namespace FastMCP.OpenApi;

/// <summary>
/// Represents an MCP tool dynamically created from an OpenAPI operation.
/// </summary>
public class OpenApiToolProxy : IDynamicMcpToolHandler
{
    private readonly OpenApiOperation _operation;
    private readonly string _path;
    private readonly OperationType _httpMethod;
     public string? Description { get; }
    public string? BaseUrl { get; }

    public OpenApiToolProxy(string name, string httpMethodString, string path, OpenApiOperation operation, string? description, string? baseUrl)
    {
         Name = name; // From IDynamicMcpToolHandler
        _path = path;
        _operation = operation;
        Description = description;
        BaseUrl = baseUrl;

        if (Enum.TryParse(httpMethodString, true, out OperationType parsedMethod))
        {
            _httpMethod = parsedMethod;
        }
        else
        {
            throw new ArgumentException($"Invalid HTTP method string: {httpMethodString}");
        }
    }

    /// <summary>
    /// The name of the MCP tool, derived from the OpenAPI operationId.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Gets the actual HTTP method (as OperationType) for the OpenAPI operation.
    /// </summary>
    public OperationType HttpMethod => _httpMethod;

    /// <summary>
    /// Gets the OpenAPI path template for the operation.
    /// </summary>
    public string Path => _path;

    /// <summary>
    /// Gets the underlying OpenApiOperation object.
    /// </summary>
    public OpenApiOperation Operation => _operation;

    /// <summary>
    /// Placeholder for executing the OpenAPI operation via HTTP.
    /// In a real implementation, this would construct and send an HTTP request
    /// based on the operation details and provided parameters.
    /// </summary>
    /// <param name="parameters">The JSON-RPC parameters for the tool.</param>
    /// <returns>The result of the HTTP call.</returns>
    public async Task<object?> ExecuteAsync(JsonElement parameters)
    {
        // TODO: Implement actual HTTP request execution here.
        // This would involve mapping JSON-RPC parameters to HTTP headers, query params, or body,
        // making an HttpClient call, and deserializing the response.
        await Task.Delay(10); // Simulate async work
        return $"Dynamic tool '{Name}' called with parameters: {parameters.GetRawText()}";
    }

    /// <summary>
    /// Gets the MethodInfo for the ExecuteAsync method for authorization purposes.
    /// </summary>
    public MethodInfo GetInvocationMethodInfo()
    {
        // This relies on the specific signature of ExecuteAsync(JsonElement parameters)
        return typeof(OpenApiToolProxy).GetMethod(nameof(ExecuteAsync), new[] { typeof(JsonElement) })!;
    }
}