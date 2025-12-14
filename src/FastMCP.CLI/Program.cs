using System;
using System.Reflection;

var cmd = args.Length > 0 ? args[0] : string.Empty;

if (string.IsNullOrEmpty(cmd) || cmd.Equals("--help", StringComparison.OrdinalIgnoreCase) || cmd.Equals("-h", StringComparison.OrdinalIgnoreCase))
{
    Console.WriteLine("FastMCP.CLI - Command-line interface for the DotnetFastMCP framework.");
    Console.WriteLine();
    Console.WriteLine("Usage:");
    Console.WriteLine("  fastmcp version    Display version information");
    Console.WriteLine();
    return;
}

switch (cmd.ToLowerInvariant())
{
    case "version":
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0";
        Console.WriteLine($"FastMCP.CLI Version: {version}");
        // In a real implementation, we would also load the core library version.
        return;
    }

    // Future commands can be added here (e.g., "run", "generate", "validate")
    default:
    {
        Console.Error.WriteLine($"Unknown command: {cmd}");
        Console.Error.WriteLine("Use --help to list available commands.");
        Environment.ExitCode = 1;
        return;
    }
}
