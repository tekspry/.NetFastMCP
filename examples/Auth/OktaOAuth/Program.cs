using FastMCP.Hosting;
using FastMCP.Server;
using System.Reflection;
using OktaOAuthServer.Tools;

try
{
    Console.WriteLine("[OktaOAuthServer] Starting...");
    
    var mcpServer = new FastMCPServer(name: "Okta OAuth Example Server");
    var builder = McpServerBuilder.Create(mcpServer, args);
    
    // Configure Okta OAuth authentication with OAuth Proxy
    builder.AddOktaTokenVerifier();
    
    builder.WithComponentsFrom(Assembly.GetExecutingAssembly());
    Console.WriteLine($"[OktaOAuthServer] Registered {mcpServer.Tools.Count} tools and {mcpServer.Resources.Count} resources");

    var app = builder.Build();
    app.Urls.Add("http://localhost:5007");
    
    Console.WriteLine("[OktaOAuthServer] Server starting on http://localhost:5007");
    Console.WriteLine("[OktaOAuthServer] MCP endpoint: http://localhost:5007/mcp");
    Console.WriteLine("[OktaOAuthServer] OAuth callback: http://localhost:5007/auth/callback");
    Console.Out.Flush();
    
    await app.RunAsync();
    
    Console.WriteLine("[OktaOAuthServer] Server stopped");
}
catch (OperationCanceledException)
{
    Console.WriteLine("[OktaOAuthServer] Server was cancelled");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[OktaOAuthServer] FATAL: {ex.Message}");
    Console.Error.WriteLine($"[OktaOAuthServer] Stack: {ex.StackTrace}");
    Environment.Exit(1);
}
