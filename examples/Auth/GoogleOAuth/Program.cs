using FastMCP.Hosting;
using FastMCP.Server;
using System.Reflection;
using GoogleOAuthServer.Tools;

try
{
    Console.WriteLine("[GoogleOAuthServer] Starting...");
    
    var mcpServer = new FastMCPServer(name: "Google OAuth Example Server");
    var builder = McpServerBuilder.Create(mcpServer, args);
    
    // Configure Google OAuth authentication with OAuth Proxy
    builder.AddGoogleTokenVerifier();
    
    // Note: AddGoogleTokenVerifier now automatically configures OAuth Proxy
    // if FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID and FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET are set
    
    builder.WithComponentsFrom(Assembly.GetExecutingAssembly());
    Console.WriteLine($"[GoogleOAuthServer] Registered {mcpServer.Tools.Count} tools and {mcpServer.Resources.Count} resources");

    var app = builder.Build();
    
    // Configure the app to listen on port 5000
    app.Urls.Add("http://localhost:5000");
    
    Console.WriteLine("[GoogleOAuthServer] Server starting on http://localhost:5000");
    Console.WriteLine("[GoogleOAuthServer] MCP endpoint: http://localhost:5000/mcp");
    Console.WriteLine("[GoogleOAuthServer] OAuth callback: http://localhost:5000/auth/callback");
    Console.Out.Flush();
    
    await app.RunAsync();
    
    Console.WriteLine("[GoogleOAuthServer] Server stopped");
}
catch (OperationCanceledException)
{
    Console.WriteLine("[GoogleOAuthServer] Server was cancelled");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[GoogleOAuthServer] FATAL: {ex.Message}");
    Console.Error.WriteLine($"[GoogleOAuthServer] Stack: {ex.StackTrace}");
    Environment.Exit(1);
}
