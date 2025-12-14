namespace FastMCP.Hosting;

/// <summary>
/// Defines constants for authentication schemes used within the FastMCP framework.
/// </summary>
public static class McpAuthenticationConstants
{
    public const string ApplicationScheme = "McpApplication"; // Default scheme for signing users in/out
    public const string ChallengeScheme = "McpChallenge"; // Default scheme for challenging unauthenticated users
}