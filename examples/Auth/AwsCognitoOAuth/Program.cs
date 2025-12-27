using FastMCP.Hosting;
using FastMCP.Server;
using System.Reflection;
using AwsCognitoOAuthServer.Tools;

try
{
    Console.WriteLine("[AwsCognitoOAuthServer] Starting...");
    
    var mcpServer = new FastMCPServer(name: "AWS Cognito OAuth Example Server");
    var builder = McpServerBuilder.Create(mcpServer, args);
    
    // Configure AWS Cognito OAuth authentication with OAuth Proxy
    builder.AddAwsCognitoTokenVerifier();
    
    builder.WithComponentsFrom(Assembly.GetExecutingAssembly());
    Console.WriteLine($"[AwsCognitoOAuthServer] Registered {mcpServer.Tools.Count} tools and {mcpServer.Resources.Count} resources");

    var app = builder.Build();
    app.Urls.Add("http://localhost:5006");
    
    Console.WriteLine("[AwsCognitoOAuthServer] Server starting on http://localhost:5006");
    Console.WriteLine("[AwsCognitoOAuthServer] MCP endpoint: http://localhost:5006/mcp");
    Console.WriteLine("[AwsCognitoOAuthServer] OAuth callback: http://localhost:5006/auth/callback");
    Console.Out.Flush();
    
    await app.RunAsync();
    
    Console.WriteLine("[AwsCognitoOAuthServer] Server stopped");
}
catch (OperationCanceledException)
{
    Console.WriteLine("[AwsCognitoOAuthServer] Server was cancelled");
}
catch (Exception ex)
{
    Console.Error.WriteLine($"[AwsCognitoOAuthServer] FATAL: {ex.Message}");
    Console.Error.WriteLine($"[AwsCognitoOAuthServer] Stack: {ex.StackTrace}");
    Environment.Exit(1);
}
