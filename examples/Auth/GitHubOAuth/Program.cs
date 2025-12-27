using FastMCP.Hosting;
using FastMCP.Server;
using System.Reflection;
using GitHubOAuthServer.Tools;

try
{
    Console.WriteLine("[GitHubOAuthServer] Starting...");
    
    var mcpServer = new FastMCPServer(name: "GitHub OAuth Example Server");
    var builder = McpServerBuilder.Create(mcpServer, args);
    
    // Configure GitHub OAuth authentication with OAuth Proxy
    builder.AddGitHubTokenVerifier();
    
    builder.WithComponentsFrom(Assembly.GetExecutingAssembly());
    Console.WriteLine($"[GitHubOAuthServer] Registered {mcpServer.Tools.Count} tools");

    var app = builder.Build();
    app.Urls.Add("http://localhost:5001");
    
    Console.WriteLine("[GitHubOAuthServer] Server starting on http://localhost:5001");
    Console.WriteLine("[GitHubOAuthServer] MCP endpoint: http://localhost:5001/mcp");
    Console.Out.Flush();
    
    await app.RunAsync();
}
catch (OperationCanceledException)
{
    Console.WriteLine("[GitHubOAuthServer] Server was cancelled");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[GitHubOAuthServer] FATAL: {ex.Message}");
    Environment.Exit(1);
}
