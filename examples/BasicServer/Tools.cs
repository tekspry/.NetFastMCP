using FastMCP.Attributes;

namespace BasicServer.Tools;

public static class Tools
{
    /// <summary>
    /// Adds two integer numbers together.
    /// </summary>
    [McpTool]
    public static int Add(int a, int b)
    {
        return a + b;
    }

    /// <summary>
    /// Multiplies two numbers.
    /// </summary>
    [McpTool]
    public static int Multiply(int a, int b)
    {
        return a * b;
    }

    /// <summary>
    /// Returns a greeting for the given name.
    /// </summary>
    [McpTool]
    public static string Greet(string name)
    {
        return $"Hello, {name}!";
    }
}
