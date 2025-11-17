using FastMCP.Attributes;

namespace BasicServer.Tools;

public static class Resources
{
    /// <summary>
    /// Provides the application's static configuration.
    /// </summary>
    [McpResource("resource://config")]
    public static object GetConfig()
    {
        return new { Version = "1.0.0", Author = "Tekspry Team" };
    }

    /// <summary>
    /// Returns a list of supported features.
    /// </summary>
    [McpResource("resource://features")]
    public static string[] GetFeatures()
    {
        return new[] { "Add", "Multiply", "Greet" };
    }

    /// <summary>
    /// Returns the current server time.
    /// </summary>
    [McpResource("resource://time")]
    public static string GetServerTime()
    {
        return DateTime.UtcNow.ToString("o");
    }
}
