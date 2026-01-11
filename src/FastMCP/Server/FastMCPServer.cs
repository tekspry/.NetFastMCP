using System.Reflection;
using FastMCP.Protocol;

namespace FastMCP.Server;

/// <summary>
/// Represents a collection of MCP components (tools, resources) that define an MCP server.
/// This class is the central point for component registration.
/// </summary>
public class FastMCPServer
{
    public string Name { get; }
    
    // Collections to store registered components
    public List<MethodInfo> Tools { get; } = new();
    public List<MethodInfo> Resources { get; } = new();
    public List<MethodInfo> Prompts { get; } = new();

    public List<Tool> ToolsMetadata { get; } = new();
    public List<Resource> ResourcesMetadata { get; } = new();
    
    // Dictionary to store OpenAPI tool proxies or other dynamic tools by name.
    // This allows the middleware to look up tool handlers by name.
    public Dictionary<string, object> DynamicTools { get; } = new(StringComparer.OrdinalIgnoreCase);

    public FastMCPServer(string name)
    {
        Name = name;
    }
}
