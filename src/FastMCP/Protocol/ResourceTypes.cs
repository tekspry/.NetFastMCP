namespace FastMCP.Protocol;

public class ListResourcesResult
{
    public List<Resource> Resources { get; set; } = new();
}

public class Resource
{
    public string Uri { get; set; } = "";
    public string Name { get; set; } = "";
    public string? Description { get; set; }
    public string? MimeType { get; set; }
}

public class ResourceContents
{
    public string Uri { get; set; } = "";
    public string? MimeType { get; set; }
    public string? Text { get; set; }
    public string? Blob { get; set; }
}
