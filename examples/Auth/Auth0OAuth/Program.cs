using FastMCP.Hosting;
using FastMCP.Server;
using System.Reflection;
using Auth0OAuthServer.Tools;

try
{
    Console.WriteLine("[Auth0OAuthServer] Starting...");
    
    var mcpServer = new FastMCPServer(name: "Auth0 OAuth Example Server");
    var builder = McpServerBuilder.Create(mcpServer, args);
    
    // Configure Auth0 OAuth authentication with OAuth Proxy
    builder.AddAuth0TokenVerifier();
    
    builder.WithComponentsFrom(Assembly.GetExecutingAssembly());
    Console.WriteLine($"[Auth0OAuthServer] Registered {mcpServer.Tools.Count} tools");

    var app = builder.Build();
    app.Urls.Add("http://localhost:5005");
    
    Console.WriteLine("[Auth0OAuthServer] Server starting on http://localhost:5005");
    Console.WriteLine("[Auth0OAuthServer] MCP endpoint: http://localhost:5005/mcp");
    Console.Out.Flush();
    
    await app.RunAsync();
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[Auth0OAuthServer] FATAL: {ex.Message}");
    Environment.Exit(1);
}
