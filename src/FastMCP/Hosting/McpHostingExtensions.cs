using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
namespace FastMCP.Hosting;
public static class McpHostingExtensions
{
    public static async Task RunMcpAsync(this WebApplication app, string[] args)
    {
        if (args.Contains("--stdio"))
        {
            var transport = app.Services.GetRequiredService<McpStdioTransport>();
            await transport.RunAsync();
        }
        else
        {
            await app.RunAsync();
        }
    }
}