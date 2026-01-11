using FastMCP.Attributes;
using FastMCP.Protocol;
using FastMCP.Server;
using Microsoft.AspNetCore.Authorization;
using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
namespace FastMCP.Hosting;
/// <summary>
/// A transport-agnostic handler for MCP JSON-RPC requests.
/// </summary>
public class McpRequestHandler
{
    private readonly IAuthorizationService _authorizationService;
    private static readonly JsonSerializerOptions _jsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    public McpRequestHandler(IAuthorizationService authorizationService)
    {
        _authorizationService = authorizationService;
    }
    /// <summary>
    /// Handles a single JSON-RPC request and returns the response.
    /// </summary>
    public async Task<JsonRpcResponse> HandleRequestAsync(JsonRpcRequest request, FastMCPServer server, ClaimsPrincipal? user)
    {
        try
        {
            if (request == null || request.JsonRpc != "2.0" || string.IsNullOrEmpty(request.Method))
            {
                return JsonRpcResponse.FromError(JsonRpcError.ErrorCodes.InvalidRequest, "Invalid JSON-RPC request.", request?.Id);
            }
            switch (request.Method)
            {
                case "prompts/list":
                    return await HandlePromptsListAsync(server, request);
                case "prompts/get":
                    return await HandlePromptsGetAsync(server, request, user);
                case "tools/list":
                    return HandleToolsList(server, request);
                case "resources/list": 
                    return HandleResourcesList(server, request);
                default:
                    return await HandleToolExecutionAsync(server, request, user);
            }
        }
        catch (Exception ex)
        {
            return JsonRpcResponse.FromError(JsonRpcError.ErrorCodes.InternalError, ex.Message, request?.Id);
        }
    }
    private Task<JsonRpcResponse> HandlePromptsListAsync(FastMCPServer server, JsonRpcRequest request)
    {
        var prompts = server.Prompts.Select(m => {
            var attr = m.GetCustomAttribute<McpPromptAttribute>();
            return new Prompt 
            {
                Name = attr?.Name ?? m.Name,
                Description = attr?.Description,
                Arguments = m.GetParameters()
                    .Where(p => p.ParameterType != typeof(ClaimsPrincipal))
                    .Select(p => new PromptArgument
                    {
                        Name = p.Name ?? "arg",
                        Description = "",
                        Required = !p.HasDefaultValue
                    }).ToList()
            };
        }).ToList();
        return Task.FromResult(new JsonRpcResponse { Id = request.Id, Result = new { prompts } });
    }
    private async Task<JsonRpcResponse> HandlePromptsGetAsync(FastMCPServer server, JsonRpcRequest request, ClaimsPrincipal? user)
    {
        try
        {
            if (request.Params is not JsonElement root || root.ValueKind != JsonValueKind.Object)
            {
                return JsonRpcResponse.FromError(JsonRpcError.ErrorCodes.InvalidParams, "Invalid params for prompts/get", request.Id);
            }
            
            if (!root.TryGetProperty("name", out var nameProp))
            {
                return JsonRpcResponse.FromError(JsonRpcError.ErrorCodes.InvalidParams, "Missing 'name' parameter", request.Id);
            }
            
            string promptName = nameProp.GetString() ?? "";
            var promptMethod = server.Prompts.FirstOrDefault(m => 
                (m.GetCustomAttribute<McpPromptAttribute>()?.Name ?? m.Name)
                .Equals(promptName, StringComparison.OrdinalIgnoreCase));
            if (promptMethod == null)
            {
                return JsonRpcResponse.FromError(JsonRpcError.ErrorCodes.MethodNotFound, $"Prompt '{promptName}' not found", request.Id);
            }
            JsonElement arguments = root.TryGetProperty("arguments", out var argsProp) ? argsProp : JsonDocument.Parse("{}").RootElement;
            // Reuse binding logic
            var args = BindParameters(promptMethod, arguments, user);
            var result = await InvokeMethodAsync(promptMethod, null, args);
            return new JsonRpcResponse { Id = request.Id, Result = result };
        }
        catch (Exception ex)
        {
             return JsonRpcResponse.FromError(JsonRpcError.ErrorCodes.InternalError, ex.InnerException?.Message ?? ex.Message, request.Id);
        }
    }
    private async Task<JsonRpcResponse> HandleToolExecutionAsync(FastMCPServer server, JsonRpcRequest request, ClaimsPrincipal? user)
    {
        // 1. Discovery
        MethodInfo? toolMethod = null;
        object? instance = null;
        toolMethod = server.Tools.FirstOrDefault(t =>
            (t.GetCustomAttribute<McpToolAttribute>()?.Name ?? t.Name)
                .Equals(request.Method, StringComparison.OrdinalIgnoreCase));
        if (toolMethod is null)
        {
            toolMethod = server.Resources.FirstOrDefault(t =>
                (t.GetCustomAttribute<McpResourceAttribute>()?.Uri?.Split('/').Last() ?? t.Name)
                    .Equals(request.Method, StringComparison.OrdinalIgnoreCase));
        }
        if (toolMethod is null && server.DynamicTools.TryGetValue(request.Method, out var dynamicToolHandler))
        {
            if (dynamicToolHandler is IDynamicMcpToolHandler mcpDynamicToolHandler)
            {
                toolMethod = mcpDynamicToolHandler.GetInvocationMethodInfo();
                instance = mcpDynamicToolHandler;
            }
        }
        if (toolMethod is null)
        {
            return JsonRpcResponse.FromError(JsonRpcError.ErrorCodes.MethodNotFound, $"Method '{request.Method}' not found.", request.Id);
        }
        // 2. Authorization
        if (!await AuthorizeMethodAsync(toolMethod, instance, user))
        {
            return JsonRpcResponse.FromError(JsonRpcError.ErrorCodes.InternalError, "Unauthorized or Forbidden.", request.Id);
        }
        // 3. Binding
        object?[] args;
        try
        {
            if (instance is IDynamicMcpToolHandler && request.Params is JsonElement)
            {
                args = new object?[] { request.Params };
            }
            else
            {
                args = BindParameters(toolMethod, request.Params, user);
            }
        }
        catch (Exception ex)
        {
            return JsonRpcResponse.FromError(JsonRpcError.ErrorCodes.InvalidParams, $"Invalid parameters: {ex.Message}", request.Id);
        }
        // 4. Invocation
        try
        {
            var result = await InvokeMethodAsync(toolMethod, instance, args);
            return new JsonRpcResponse { Id = request.Id, Result = result };
        }
        catch (Exception ex)
        {
            return JsonRpcResponse.FromError(JsonRpcError.ErrorCodes.InternalError, $"Method execution error: {ex.InnerException?.Message ?? ex.Message}", request.Id);
        }
    }
    private async Task<bool> AuthorizeMethodAsync(MethodInfo method, object? instance, ClaimsPrincipal? user)
    {
        // If no user is present (e.g. Stdio), we might skip auth or enforce policy depending on requirements.
        // For Stdio, user is often null.
        if (user == null) return true; // TODO: Decide on Stdio Auth Policy
        var authorizeAttribute = method.GetCustomAttribute<AuthorizeMcpToolAttribute>();
        var standardAuthorizeAttribute = method.GetCustomAttribute<AuthorizeAttribute>();
        
        if (authorizeAttribute == null && standardAuthorizeAttribute == null)
        {
            return true;
        }
        var policyBuilder = new AuthorizationPolicyBuilder();
        if (authorizeAttribute != null)
        {
            if (!string.IsNullOrEmpty(authorizeAttribute.Policy))
                policyBuilder.AddRequirements(new PolicyNameRequirement(authorizeAttribute.Policy));
            if (!string.IsNullOrEmpty(authorizeAttribute.Roles))
                policyBuilder.RequireRole(authorizeAttribute.Roles.Split(',', StringSplitOptions.RemoveEmptyEntries));
            if (!string.IsNullOrEmpty(authorizeAttribute.AuthenticationSchemes))
                policyBuilder.AddAuthenticationSchemes(authorizeAttribute.AuthenticationSchemes.Split(',', StringSplitOptions.RemoveEmptyEntries));
        }
        
        if (standardAuthorizeAttribute != null)
        {
            if (!string.IsNullOrEmpty(standardAuthorizeAttribute.Policy))
                policyBuilder.AddRequirements(new PolicyNameRequirement(standardAuthorizeAttribute.Policy));
            if (!string.IsNullOrEmpty(standardAuthorizeAttribute.Roles))
                policyBuilder.RequireRole(standardAuthorizeAttribute.Roles.Split(',', StringSplitOptions.RemoveEmptyEntries));
            if (standardAuthorizeAttribute.AuthenticationSchemes != null)
                policyBuilder.AddAuthenticationSchemes(standardAuthorizeAttribute.AuthenticationSchemes.Split(',', StringSplitOptions.RemoveEmptyEntries));
        }
        if (!policyBuilder.Requirements.Any() && policyBuilder.AuthenticationSchemes.Count == 0)
        {
            policyBuilder.RequireAuthenticatedUser();
        }
        var policy = policyBuilder.Build();
        var authorizationResult = await _authorizationService.AuthorizeAsync(user, instance, policy);
        return authorizationResult.Succeeded;
    }
    private async Task<object?> InvokeMethodAsync(MethodInfo method, object? instance, object?[] args)
    {
        var result = method.Invoke(instance, args);
        if (result is Task task)
        {
            await task.ConfigureAwait(false);
            var resultProperty = task.GetType().GetProperty("Result");
            return resultProperty?.GetValue(task);
        }
        return result;
    }
    private object?[] BindParameters(MethodInfo method, object? rpcParams, ClaimsPrincipal? user)
    {
        var methodParams = method.GetParameters();
        if (methodParams.Length == 0) 
            return Array.Empty<object>();
        var args = new object?[methodParams.Length];
        
        for (int i = 0; i < methodParams.Length; i++)
        {
            if (methodParams[i].ParameterType == typeof(ClaimsPrincipal))
            {
                args[i] = user;
            }
        }
        if (rpcParams is null)
        {
            FillMissingParamsWithDefaults(methodParams, args);
            return args;
        }
        if (rpcParams is not JsonElement paramsElement)
        {
            var json = JsonSerializer.Serialize(rpcParams);
            using var doc = JsonDocument.Parse(json);
            paramsElement = doc.RootElement.Clone(); // Clone to be safe, though not strictly needed
            return BindJsonElement(paramsElement, methodParams, args);
        }
        return BindJsonElement((JsonElement)rpcParams, methodParams, args);
    }
    
    // ... [BindJsonElement, BindObjectParameters, BindArrayParameters, FillMissingParamsWithDefaults] 
    // (These helper methods are identical to the Middleware ones and would be copied here)
    
    // COPIED HELPERS BELOW (For completeness in preview)
    
    private object?[] BindJsonElement(JsonElement paramsElement, ParameterInfo[] methodParams, object?[] args)
    {
        if (paramsElement.ValueKind == JsonValueKind.Object)
        {
            BindObjectParameters(paramsElement, methodParams, args);
        }
        else if (paramsElement.ValueKind == JsonValueKind.Array)
        {
            BindArrayParameters(paramsElement, methodParams, args);
        }
        else
        {
            throw new InvalidOperationException("Parameters must be an object or an array.");
        }
        return args;
    }
    private void FillMissingParamsWithDefaults(ParameterInfo[] methodParams, object?[] args)
    {
        for (int i = 0; i < methodParams.Length; i++)
        {
            if (args[i] != null) continue;
            if (methodParams[i].HasDefaultValue)
                args[i] = methodParams[i].DefaultValue;
            else
                throw new InvalidOperationException($"Missing required parameter: {methodParams[i].Name}");
        }
    }
    private void BindObjectParameters(JsonElement paramsElement, ParameterInfo[] methodParams, object?[] args)
    {
        for (int i = 0; i < methodParams.Length; i++)
        {
            if (args[i] != null) continue;
            var param = methodParams[i];
            var paramProp = paramsElement.EnumerateObject()
                .FirstOrDefault(p => p.Name.Equals(param.Name, StringComparison.OrdinalIgnoreCase));
            
            if (paramProp.Value.ValueKind != JsonValueKind.Undefined)
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
    }
    private void BindArrayParameters(JsonElement paramsElement, ParameterInfo[] methodParams, object?[] args)
    {
        var paramsArray = paramsElement.EnumerateArray().ToList();
        
        for (int i = 0; i < methodParams.Length; i++)
        {
            if (args[i] != null) continue;
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
    }

    private JsonRpcResponse HandleToolsList(FastMCPServer server, JsonRpcRequest request)
    {
        var tools = server.Tools.Select(t => {
            var attr = t.GetCustomAttribute<McpToolAttribute>();
            return new Tool
            {
                Name = attr?.Name ?? t.Name,
                Description = attr?.Description ?? "",
                InputSchema = GenerateSchema(t)
            };
        }).ToList();
        // Add Dynamic tools if any
        foreach (var dynamicTool in server.DynamicTools)
        {
             // Simplified schema for dynamic tools - you may want to expand this if your dynamic tools support schema
             tools.Add(new Tool { Name = dynamicTool.Key, Description = "Dynamic Tool" });
        }
        return new JsonRpcResponse { Id = request.Id, Result = new ListToolsResult { Tools = tools } };
    }
    private JsonRpcResponse HandleResourcesList(FastMCPServer server, JsonRpcRequest request)
    {
        var resources = server.Resources.Select(method => {
            var attr = method.GetCustomAttribute<McpResourceAttribute>();
            return new Resource
            {
                Uri = attr?.Uri ?? "",
                Name = attr?.Name ?? method.Name,
                Description = attr?.Description,
                MimeType = attr?.MimeType
            };
        }).ToList();
        return new JsonRpcResponse { Id = request.Id, Result = new ListResourcesResult { Resources = resources } };
    }
    private InputSchema GenerateSchema(MethodInfo method)
    {
        var schema = new InputSchema();
        foreach (var param in method.GetParameters())
        {
            if (param.ParameterType == typeof(ClaimsPrincipal)) continue; // Skip injected dependencies
            string typeName = param.ParameterType == typeof(int) || param.ParameterType == typeof(long) ? "integer" :
                              param.ParameterType == typeof(bool) ? "boolean" : "string";
            schema.Properties[param.Name ?? "arg"] = new { type = typeName };
            if (!param.HasDefaultValue)
            {
                schema.Required.Add(param.Name ?? "arg");
            }
        }
        return schema;
    }
}