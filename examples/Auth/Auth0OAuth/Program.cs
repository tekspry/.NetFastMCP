using FastMCP.Hosting;
using FastMCP.Server;
using System.Reflection;
using OktaOAuthServer.Tools;

try
{
    Console.WriteLine("[OktaOAuthServer] Starting...");
    
    var mcpServer = new FastMCPServer(name: "Okta OAuth Example Server");
    var builder = McpServerBuilder.Create(mcpServer, args);
    
    // Configure Okta OAuth using OAuth Proxy
    builder.AddOktaOAuthProxy();
    
    builder.WithComponentsFrom(Assembly.GetExecutingAssembly());
    Console.WriteLine($"[OktaOAuthServer] Registered {mcpServer.Tools.Count} tools");

    var app = builder.Build();
    app.Urls.Add("http://localhost:5005");
    
    Console.WriteLine("[OktaOAuthServer] Server starting on http://localhost:5005");
    Console.WriteLine("[OktaOAuthServer] MCP endpoint: http://localhost:5005/mcp");
    Console.Out.Flush();
    
    await app.RunAsync();
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[OktaOAuthServer] FATAL: {ex.Message}");
    Environment.Exit(1);
}
