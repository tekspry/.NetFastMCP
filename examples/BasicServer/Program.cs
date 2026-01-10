using FastMCP.Hosting;
using FastMCP.Server;
using System.Reflection;
using BasicServer.Tools;

try
{
    Console.Error.WriteLine("[BasicServer] Starting...");
    
    var mcpServer = new FastMCPServer(name: "My First Dotnet MCP Server");
    var builder = McpServerBuilder.Create(mcpServer, args);
    builder.WithComponentsFrom(Assembly.GetExecutingAssembly());
    
    Console.Error.WriteLine($"[BasicServer] Registered {mcpServer.Tools.Count} tools and {mcpServer.Resources.Count} resources");

    var app = builder.Build();
    Console.Error.WriteLine("[BasicServer] App built, starting to run...");
    await app.RunMcpAsync(args);
    Console.Error.WriteLine("[BasicServer] App finished running");
}
catch (OperationCanceledException)
{
    Console.Error.WriteLine("[BasicServer] App was cancelled");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[BasicServer] FATAL: {ex.Message}");
    Console.Error.WriteLine($"[BasicServer] Stack: {ex.StackTrace}");
    Environment.Exit(1);
}
