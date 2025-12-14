using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FastMCP.Authentication.Core;
using Microsoft.Extensions.Logging;

namespace FastMCP.Authentication.Providers.GitHub;

/// <summary>
/// Token verifier for GitHub OAuth tokens.
/// GitHub OAuth tokens are opaque (not JWTs), so we verify them
/// by calling GitHub's API to check if they're valid and get user info.
/// </summary>
public class GitHubTokenVerifier : ITokenVerifier
{
    private readonly IReadOnlyList<string> _requiredScopes;
    private readonly int _timeoutSeconds;
    private readonly ILogger<GitHubTokenVerifier>? _logger;
    private readonly HttpClient _httpClient;

    public GitHubTokenVerifier(
        IReadOnlyList<string>? requiredScopes = null,
        int timeoutSeconds = 10,
        ILogger<GitHubTokenVerifier>? logger = null,
        HttpClient? httpClient = null)
    {
        _requiredScopes = requiredScopes ?? new[] { "user" };
        _timeoutSeconds = timeoutSeconds;
        _logger = logger;
        _httpClient = httpClient ?? new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(timeoutSeconds)
        };
        _httpClient.DefaultRequestHeaders.Add("Accept", "application/vnd.github.v3+json");
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "FastMCP-GitHub-OAuth");
    }

    public IReadOnlyList<string> RequiredScopes => _requiredScopes;

    public async Task<AccessToken?> VerifyTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            _logger?.LogDebug("Token verification failed: token is null or empty");
            return null;
        }

        try
        {
            // Get user info from GitHub API
            var request = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/user");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            
            var response = await _httpClient.SendAsync(request, cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                _logger?.LogDebug("GitHub token verification failed: HTTP {StatusCode}", (int)response.StatusCode);
                return null;
            }

            var userData = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken);

            // Get token scopes from GitHub API (included in response headers)
            var tokenScopes = new List<string>();
            if (response.Headers.TryGetValues("X-OAuth-Scopes", out var scopeHeaders))
            {
                var scopeHeader = scopeHeaders.FirstOrDefault() ?? string.Empty;
                tokenScopes = scopeHeader
                    .Split(',', StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim())
                    .Where(s => !string.IsNullOrEmpty(s))
                    .ToList();
            }

            // If no scopes in header, assume basic scope if we can access user info
            if (tokenScopes.Count == 0)
            {
                tokenScopes.Add("user");
            }

            // Check required scopes
            if (_requiredScopes.Count > 0)
            {
                var tokenScopesSet = new HashSet<string>(tokenScopes, StringComparer.OrdinalIgnoreCase);
                var requiredScopesSet = new HashSet<string>(_requiredScopes, StringComparer.OrdinalIgnoreCase);
                if (!requiredScopesSet.IsSubsetOf(tokenScopesSet))
                {
                    _logger?.LogDebug(
                        "GitHub token missing required scopes. Has {TokenScopes}, needs {RequiredScopes}",
                        tokenScopesSet.Count,
                        requiredScopesSet.Count);
                    return null;
                }
            }

            // Extract user ID
            var userId = userData.TryGetProperty("id", out var idElement)
                ? idElement.GetInt64().ToString()
                : "unknown";

            // Extract claims
            var claims = new Dictionary<string, object>
            {
                ["sub"] = userId,
                ["login"] = userData.TryGetProperty("login", out var login) ? login.GetString() ?? string.Empty : string.Empty,
                ["name"] = userData.TryGetProperty("name", out var name) ? name.GetString() ?? string.Empty : string.Empty,
                ["email"] = userData.TryGetProperty("email", out var email) ? email.GetString() ?? string.Empty : string.Empty,
                ["avatar_url"] = userData.TryGetProperty("avatar_url", out var avatar) ? avatar.GetString() ?? string.Empty : string.Empty
            };

            _logger?.LogDebug("GitHub token verified successfully for user {UserId}", userId);

            return new AccessToken
            {
                Token = token,
                ClientId = userId,
                Scopes = tokenScopes,
                ExpiresAt = null, // GitHub tokens don't typically expire
                Claims = claims
            };
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "GitHub token verification error");
            return null;
        }
    }
}