namespace FastMCP.Protocol;

public class ListToolsResult
{
    public List<Tool> Tools { get; set; } = new();
}

public class Tool
{
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public InputSchema InputSchema { get; set; } = new();
}

public class InputSchema
{
    public string Type { get; set; } = "object";
    public Dictionary<string, object> Properties { get; set; } = new();
    public List<string> Required { get; set; } = new();
}