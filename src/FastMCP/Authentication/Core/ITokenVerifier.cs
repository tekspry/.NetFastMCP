using System.Collections.Generic;
using System.Threading.Tasks;

namespace FastMCP.Authentication.Core;

/// <summary>
/// Interface for verifying bearer tokens.
/// All authentication providers must implement token verification.
/// </summary>
public interface ITokenVerifier
{
    /// <summary>
    /// Verifies a bearer token and returns access information if valid.
    /// </summary>
    /// <param name="token">The token string to validate.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// AccessToken object if valid, null if invalid or expired.
    /// </returns>
    Task<AccessToken?> VerifyTokenAsync(string token, CancellationToken cancellationToken = default);

    /// <summary>
    /// List of OAuth scopes required for all tokens verified by this verifier.
    /// Empty list means no scope validation is performed.
    /// </summary>
    IReadOnlyList<string> RequiredScopes { get; }
}