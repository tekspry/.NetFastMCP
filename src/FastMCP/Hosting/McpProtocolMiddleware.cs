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
    private readonly IAuthorizationService _authorizationService; // Injected
    private static readonly JsonSerializerOptions _jsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    
    public McpProtocolMiddleware(RequestDelegate next, IAuthorizationService authorizationService)
    {
        _next = next;
         _authorizationService = authorizationService;
    }

    public async Task InvokeAsync(HttpContext context, FastMCPServer server)
    {
        try
        {
            Console.WriteLine($"[Middleware] Processing request: {context.Request.Method} {context.Request.Path}");
            
            // Only process MCP requests to /mcp endpoint
            if (context.Request.Path != "/mcp" || !HttpMethods.IsPost(context.Request.Method))
            {
                Console.WriteLine($"[Middleware] Not an MCP request, passing to next middleware");
                await _next(context);
                return;
            }

            Console.WriteLine("[Middleware] Processing MCP request...");
            context.Response.ContentType = "application/json";
            JsonRpcRequest? request;
            try
            {
                request = await JsonSerializer.DeserializeAsync<JsonRpcRequest>(context.Request.Body, _jsonOptions);
                Console.WriteLine($"[Middleware] Deserialized request: method={request?.Method}");
            }
            catch (JsonException ex)
            {
                Console.WriteLine($"[Middleware] JSON parse error: {ex.Message}");
                var response = JsonRpcResponse.FromError(
                    JsonRpcError.ErrorCodes.ParseError, 
                    $"JSON parse error: {ex.Message}", 
                    null);
                await JsonSerializer.SerializeAsync(context.Response.Body, response, _jsonOptions);
                return;
            }

            if (request is null || request.JsonRpc != "2.0" || string.IsNullOrEmpty(request.Method))
            {
                Console.WriteLine("[Middleware] Invalid request format");
                var response = JsonRpcResponse.FromError(
                    JsonRpcError.ErrorCodes.InvalidRequest, 
                    "Invalid JSON-RPC request.", 
                    request?.Id);
                await JsonSerializer.SerializeAsync(context.Response.Body, response, _jsonOptions);
                return;
            }
            
            MethodInfo? toolMethod = null;
            object? instance = null; 
            
            // Find method in Tools, then Resources
            toolMethod = server.Tools.FirstOrDefault(t =>
                (t.GetCustomAttribute<McpToolAttribute>()?.Name ?? t.Name)
                    .Equals(request.Method, StringComparison.OrdinalIgnoreCase));
            
            if (toolMethod is null)
            {
                // For resources, use the method name for invocation (not the URI which is metadata)
                toolMethod = server.Resources.FirstOrDefault(t =>
                    (t.GetCustomAttribute<McpResourceAttribute>()?.Uri?.Split('/').Last() ?? t.Name)
                        .Equals(request.Method, StringComparison.OrdinalIgnoreCase));
            }

            // Handle dynamic tools (e.g., OpenAPI proxies)
            if (toolMethod is null && server.DynamicTools.TryGetValue(request.Method, out var dynamicToolHandler))
            {
                // For dynamic tools, we'll wrap the `ExecuteAsync` method of the proxy
                // to allow it to be invoked and potentially authorized.
                // This is a simplification; a full solution for dynamic tool auth is more complex
                // and might involve an `IMcpToolHandler` interface.
                if (dynamicToolHandler is IDynamicMcpToolHandler mcpDynamicToolHandler) // Use the interface
                {
                    toolMethod = mcpDynamicToolHandler.GetInvocationMethodInfo(); // Get MethodInfo from the handler
                    instance = mcpDynamicToolHandler; // Provide the instance for invocation
                }
            }

            if (toolMethod is null)
            {
                Console.WriteLine($"[Middleware] Method '{request.Method}' not found");
                var response = JsonRpcResponse.FromError(
                    JsonRpcError.ErrorCodes.MethodNotFound, 
                    $"Method '{request.Method}' not found.", 
                    request.Id);
                await JsonSerializer.SerializeAsync(context.Response.Body, response, _jsonOptions);
                return;
            }

            // --- Authorization Check ---
            var authorizeAttribute = toolMethod.GetCustomAttribute<AuthorizeMcpToolAttribute>();
            if (authorizeAttribute != null)
            {
                var policyBuilder = new AuthorizationPolicyBuilder();

                if (!string.IsNullOrEmpty(authorizeAttribute.Policy))
                {
                    policyBuilder.AddRequirements(new PolicyNameRequirement(authorizeAttribute.Policy));
                }
                if (!string.IsNullOrEmpty(authorizeAttribute.Roles))
                {
                    policyBuilder.RequireRole(authorizeAttribute.Roles.Split(',', StringSplitOptions.RemoveEmptyEntries));
                }
                if (!string.IsNullOrEmpty(authorizeAttribute.AuthenticationSchemes))
                {
                    policyBuilder.AddAuthenticationSchemes(authorizeAttribute.AuthenticationSchemes.Split(',', StringSplitOptions.RemoveEmptyEntries));
                }

                // If no specific policy/roles/schemes are defined, it just requires an authenticated user
                if (!policyBuilder.Requirements.Any() && policyBuilder.AuthenticationSchemes.Count == 0)
                {
                    policyBuilder.RequireAuthenticatedUser();
                }

                var policy = policyBuilder.Build();
                
                var authorizationResult = await _authorizationService.AuthorizeAsync(context.User, instance, policy);

                if (!authorizationResult.Succeeded)
                {
                    Console.WriteLine($"[Middleware] Authorization failed for method '{request.Method}' (User: {context.User.Identity?.Name ?? "Anonymous"})");
                    
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized; // Set HTTP status for browser clients

                    // Return a JSON-RPC error indicating unauthorized/forbidden
                    var errorResponse = JsonRpcResponse.FromError(
                        JsonRpcError.ErrorCodes.InternalError, // You might define a custom error code for unauthorized/forbidden
                        "Unauthorized or Forbidden. User might not be authenticated or lack necessary permissions.",
                        request.Id);
                    await JsonSerializer.SerializeAsync(context.Response.Body, errorResponse, _jsonOptions);
                    return;
                }
                Console.WriteLine($"[Middleware] Authorization successful for method '{request.Method}' (User: {context.User.Identity?.Name ?? "Anonymous"})");
            }
            // --- End Authorization Check ---

            object?[] args;
            try
            {
                Console.WriteLine($"[Middleware] Binding parameters for {request.Method}...");
                 // If it's an OpenApiToolProxy, the ExecuteAsync method expects a JsonElement
                if (instance is IDynamicMcpToolHandler && request.Params is JsonElement)
                {
                    args = new object?[] { request.Params };
                }
                else
                {
                    args = BindParameters(toolMethod, request.Params, context.User);
                }
                Console.WriteLine($"[Middleware] Parameter binding successful");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Middleware] Parameter binding error: {ex.Message}");
                var response = JsonRpcResponse.FromError(
                    JsonRpcError.ErrorCodes.InvalidParams, 
                    $"Invalid parameters: {ex.Message}", 
                    request.Id);
                await JsonSerializer.SerializeAsync(context.Response.Body, response, _jsonOptions);
                return;
            }

            try
            {
                Console.WriteLine($"[Middleware] Invoking method {request.Method}...");
                
                // If it's a static method, instance is null. If it's a dynamic proxy, instance is the proxy object.
                var result = await (Task<object?>)toolMethod.Invoke(instance, args)!; 
                
                Console.WriteLine($"[Middleware] Method invocation successful, result={result}");
                var response = new JsonRpcResponse { Id = request.Id, Result = result };
                await JsonSerializer.SerializeAsync(context.Response.Body, response, _jsonOptions);
                Console.WriteLine("[Middleware] Response sent successfully");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Middleware] Method execution error: {ex.InnerException?.Message ?? ex.Message}");
                var response = JsonRpcResponse.FromError(
                    JsonRpcError.ErrorCodes.InternalError, 
                    $"Method execution error: {ex.InnerException?.Message ?? ex.Message}", 
                    request.Id);
                await JsonSerializer.SerializeAsync(context.Response.Body, response, _jsonOptions);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Middleware] UNHANDLED EXCEPTION: {ex}");
            Console.WriteLine($"[Middleware] Stack: {ex.StackTrace}");
            try
            {
                context.Response.ContentType = "application/json";
                var errorResponse = JsonRpcResponse.FromError(
                    JsonRpcError.ErrorCodes.InternalError, 
                    "Internal server error", 
                    null);
                await JsonSerializer.SerializeAsync(context.Response.Body, errorResponse, _jsonOptions);
            }
            catch
            {
                // If we can't send a response, the connection will be closed anyway
            }
        }
    }

    /// <summary>
    /// Binds JSON-RPC parameters to method parameters.
    /// Supports both array-style (positional) and object-style (named) parameters.
    /// </summary>
    private object?[] BindParameters(MethodInfo method, object? rpcParams, ClaimsPrincipal? user = null)
    {
        var methodParams = method.GetParameters();
        if (methodParams.Length == 0) 
            return Array.Empty<object>();

        var args = new object?[methodParams.Length];
        
        // Check if any parameter is of type ClaimsPrincipal or AccessToken
        for (int i = 0; i < methodParams.Length; i++)
        {
            var param = methodParams[i];
            
            // Inject ClaimsPrincipal if requested
            if (param.ParameterType == typeof(ClaimsPrincipal))
            {
                args[i] = user;
                continue;
            }
            
            // Inject AccessToken if requested (requires token verification)
            // TODO: Implement token extraction and verification if needed
        }


        // Handle null parameters
        if (rpcParams is null)
        {
            for (int i = 0; i < methodParams.Length; i++)
            {
                var param = methodParams[i];
                if (param.HasDefaultValue)
                {
                    args[i] = param.DefaultValue;
                }
                else
                {
                    throw new InvalidOperationException($"Missing required parameter: {param.Name}");
                }
            }
            return args;
        }

        // Convert to JsonElement if needed
        if (rpcParams is not JsonElement paramsElement)
        {
            var json = JsonSerializer.Serialize(rpcParams);
            using var doc = JsonDocument.Parse(json);
            paramsElement = doc.RootElement;
            
            // Handle object and array immediately within using scope
            if (paramsElement.ValueKind == JsonValueKind.Object)
            {
                return BindObjectParameters(paramsElement, methodParams);
            }
            else if (paramsElement.ValueKind == JsonValueKind.Array)
            {
                return BindArrayParameters(paramsElement, methodParams);
            }
        }

        // Process JsonElement directly
        if (paramsElement.ValueKind == JsonValueKind.Object)
        {
            return BindObjectParameters(paramsElement, methodParams);
        }
        else if (paramsElement.ValueKind == JsonValueKind.Array)
        {
            return BindArrayParameters(paramsElement, methodParams);
        }
        else
        {
            throw new InvalidOperationException("Parameters must be an object or an array.");
        }
    }

    private object?[] BindObjectParameters(JsonElement paramsElement, ParameterInfo[] methodParams)
    {
        var args = new object?[methodParams.Length];
        for (int i = 0; i < methodParams.Length; i++)
        {
            var param = methodParams[i];
            var paramProp = paramsElement.EnumerateObject()
                .FirstOrDefault(p => p.Name.Equals(param.Name, StringComparison.OrdinalIgnoreCase));
            
            if (!paramProp.Equals(default(JsonProperty)))
            {
                args[i] = paramProp.Value.Deserialize(param.ParameterType, _jsonOptions);
            }
            else if (param.HasDefaultValue)
            {
                args[i] = param.DefaultValue;
            }
            else
            {
                throw new InvalidOperationException($"Missing required parameter: {param.Name}");
            }
        }
        return args;
    }

    private object?[] BindArrayParameters(JsonElement paramsElement, ParameterInfo[] methodParams)
    {
        var args = new object?[methodParams.Length];
        var paramsArray = paramsElement.EnumerateArray().ToList();
        
        for (int i = 0; i < methodParams.Length; i++)
        {
            if (i < paramsArray.Count)
            {
                args[i] = paramsArray[i].Deserialize(methodParams[i].ParameterType, _jsonOptions);
            }
            else if (methodParams[i].HasDefaultValue)
            {
                args[i] = methodParams[i].DefaultValue;
            }
            else
            {
                throw new InvalidOperationException($"Missing required parameter: {methodParams[i].Name}");
            }
        }
        return args;
    }
}

public static class McpServerExtensions
{
    public static IApplicationBuilder UseMcpProtocol(this IApplicationBuilder app)
    {
        return app.UseMiddleware<McpProtocolMiddleware>();
    }
}
