using System.Reflection;
using System.Text.Json;
using System.Threading.Tasks;

namespace FastMCP.Server;

/// <summary>
/// Defines an interface for dynamic MCP tool handlers.
/// This allows the core FastMCP middleware to invoke dynamic tools
/// without having a direct dependency on their specific implementations (e.g., OpenApiToolProxy).
/// </summary>
public interface IDynamicMcpToolHandler
{
    /// <summary>
    /// Gets the name of the dynamic tool/method.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Executes the dynamic MCP tool with the given parameters.
    /// </summary>
    /// <param name="parameters">The JSON-RPC parameters as a JsonElement.</param>
    /// <returns>The result of the tool invocation.</returns>
    Task<object?> ExecuteAsync(JsonElement parameters);

    /// <summary>
    /// Gets the MethodInfo representation of the ExecuteAsync method for authorization purposes.
    /// This allows AuthorizationMiddleware to apply policies to dynamic tools.
    /// </summary>
    /// <returns>A MethodInfo representing the executable action of the dynamic tool.</returns>
    MethodInfo GetInvocationMethodInfo();
}