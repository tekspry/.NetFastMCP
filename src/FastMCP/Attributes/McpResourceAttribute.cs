namespace FastMCP.Attributes;

/// <summary>
/// Marks a method as an MCP resource provider.
/// The method should return the content of the resource.
/// </summary>
[AttributeUsage(AttributeTargets.Method, Inherited = false, AllowMultiple = false)]
public sealed class McpResourceAttribute : Attribute
{
    public string Uri { get; }
    public string? Name { get; set; }
    public string? Description { get; set; }
    public string? MimeType { get; set; }
    
    public McpResourceAttribute(string uri, string? name = null)
    {
        Uri = uri;
        Name = name;
    }
}
