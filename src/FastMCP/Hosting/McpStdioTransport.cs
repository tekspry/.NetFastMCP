using FastMCP.Protocol;
using FastMCP.Server;
using Microsoft.Extensions.Logging;
using System.Text.Json;
namespace FastMCP.Hosting;
/// <summary>
/// Implements the MCP Standard Input/Output (stdio) transport.
/// </summary>
public class McpStdioTransport
{
    private readonly McpRequestHandler _requestHandler;
    private readonly FastMCPServer _server;
    private readonly ILogger<McpStdioTransport> _logger;
    private static readonly JsonSerializerOptions _jsonOptions = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    public McpStdioTransport(McpRequestHandler requestHandler, FastMCPServer server, ILogger<McpStdioTransport> logger)
    {
        _requestHandler = requestHandler;
        _server = server;
        _logger = logger;
    }
    /// <summary>
    /// Starts the Stdio transport loop. This method blocks until the input stream checks close.
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Starting Stdio Transport...");
        
        // In Stdio mode, we CANNOT write logs to stdout, as it's reserved for JSON-RPC.
        // Users should configure logging to stderr or file.
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                // Read line from Stdin
                var line = await Console.In.ReadLineAsync(cancellationToken);
                if (line == null) break; // End of stream
                if (string.IsNullOrWhiteSpace(line)) continue;
                // Process Request
                _logger.LogDebug("Received Stdio Message");
                
                JsonRpcRequest? request = null;
                try 
                {
                    request = JsonSerializer.Deserialize<JsonRpcRequest>(line, _jsonOptions);
                }
                catch (JsonException)
                {
                    // Invalid JSON, ignore or send parse error? 
                    // MCP Spec says we should send error if possible, but if we can't parse ID, we can't reply effectively.
                    // Let's try to send a ParseError without ID.
                     var error = JsonRpcResponse.FromError(JsonRpcError.ErrorCodes.ParseError, "Parse error", null);
                     await SendResponseAsync(error);
                     continue;
                }
                if (request != null)
                {
                    // Handle and Reply
                    var response = await _requestHandler.HandleRequestAsync(request, _server, null); // User is null for Stdio
                    await SendResponseAsync(response);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Stdio Transport Fatal Error");
        }
    }
    private async Task SendResponseAsync(JsonRpcResponse response)
    {
        var json = JsonSerializer.Serialize(response, _jsonOptions);
        await Console.Out.WriteLineAsync(json);
        await Console.Out.FlushAsync();
    }
}