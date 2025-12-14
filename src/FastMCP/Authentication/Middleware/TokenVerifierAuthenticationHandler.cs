using System.Security.Claims;
using System.Text.Encodings.Web;
using FastMCP.Authentication.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FastMCP.Authentication.Middleware;

/// <summary>
/// ASP.NET Core authentication handler that uses ITokenVerifier to validate bearer tokens.
/// This handler extracts bearer tokens from the Authorization header and validates them
/// using the configured token verifier, then creates a ClaimsPrincipal for authorization.
/// </summary>
public class TokenVerifierAuthenticationHandler : AuthenticationHandler<TokenVerifierAuthenticationOptions>
{
    private readonly ITokenVerifier _tokenVerifier;

    public TokenVerifierAuthenticationHandler(
        IOptionsMonitor<TokenVerifierAuthenticationOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ITokenVerifier tokenVerifier)
        : base(options, logger, encoder)
    {
        _tokenVerifier = tokenVerifier ?? throw new ArgumentNullException(nameof(tokenVerifier));
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Extract bearer token from Authorization header
        if (!Request.Headers.ContainsKey("Authorization"))
        {
            return AuthenticateResult.NoResult();
        }

        var authHeader = Request.Headers["Authorization"].ToString();
        if (string.IsNullOrWhiteSpace(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.NoResult();
        }

        var token = authHeader.Substring("Bearer ".Length).Trim();
        if (string.IsNullOrWhiteSpace(token))
        {
            return AuthenticateResult.NoResult();
        }

        try
        {
            // Verify the token using the token verifier
            var accessToken = await _tokenVerifier.VerifyTokenAsync(token, Context.RequestAborted);

            if (accessToken == null)
            {
                Logger.LogDebug("Token verification failed: invalid or expired token");
                return AuthenticateResult.Fail("Invalid or expired token");
            }

            // Check if token is expired
            if (accessToken.IsExpired)
            {
                Logger.LogDebug("Token verification failed: token has expired");
                return AuthenticateResult.Fail("Token has expired");
            }

            // Validate required scopes if specified
            if (_tokenVerifier.RequiredScopes.Count > 0 && !accessToken.HasRequiredScopes(_tokenVerifier.RequiredScopes))
            {
                Logger.LogDebug(
                    "Token verification failed: missing required scopes. Required: {RequiredScopes}",
                    string.Join(", ", _tokenVerifier.RequiredScopes));
                return AuthenticateResult.Fail("Token missing required scopes");
            }

            // Create claims from the access token
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, accessToken.ClientId),
                new Claim("client_id", accessToken.ClientId)
            };

            // Add scope claims
            foreach (var scope in accessToken.Scopes)
            {
                claims.Add(new Claim("scope", scope));
            }

            // Add all claims from the token
            foreach (var claim in accessToken.Claims)
            {
                // Map common claim types
                var claimType = claim.Key.ToLowerInvariant() switch
                {
                    "sub" => ClaimTypes.NameIdentifier,
                    "email" => ClaimTypes.Email,
                    "name" => ClaimTypes.Name,
                    "given_name" => ClaimTypes.GivenName,
                    "family_name" => ClaimTypes.Surname,
                    _ => claim.Key
                };

                // Handle different claim value types
                if (claim.Value is string stringValue)
                {
                    claims.Add(new Claim(claimType, stringValue));
                }
                else if (claim.Value is IEnumerable<object> arrayValue)
                {
                    foreach (var item in arrayValue)
                    {
                        claims.Add(new Claim(claimType, item.ToString() ?? string.Empty));
                    }
                }
                else
                {
                    claims.Add(new Claim(claimType, claim.Value.ToString() ?? string.Empty));
                }
            }

            // Create identity and principal
            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            Logger.LogDebug("Token verified successfully for client {ClientId}", accessToken.ClientId);

            return AuthenticateResult.Success(ticket);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Error during token verification");
            return AuthenticateResult.Fail($"Token verification error: {ex.Message}");
        }
    }
}

/// <summary>
/// Options for TokenVerifierAuthenticationHandler.
/// </summary>
public class TokenVerifierAuthenticationOptions : AuthenticationSchemeOptions
{
    // Options can be extended here if needed
}