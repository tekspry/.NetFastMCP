using System.Collections.Generic;

namespace FastMCP.Authentication.Configuration;

/// <summary>
/// Configuration options for AWS Cognito authentication.
/// </summary>
public class AwsCognitoAuthOptions
{
    public string? UserPoolId { get; set; }
    public string AwsRegion { get; set; } = "us-east-1";
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; }
    public string? Audience { get; set; }
    public IReadOnlyList<string>? RequiredScopes { get; set; } = new[] { "openid" };
}