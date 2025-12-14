using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FastMCP.Authentication.Core;
using Microsoft.Extensions.Logging;

namespace FastMCP.Authentication.Providers.Google;

/// <summary>
/// Token verifier for Google OAuth tokens.
/// Google OAuth tokens are opaque (not JWTs), so we verify them
/// by calling Google's tokeninfo API to check if they're valid and get user info.
/// </summary>
public class GoogleTokenVerifier : ITokenVerifier
{
    private readonly string? _clientId;
    private readonly IReadOnlyList<string> _requiredScopes;
    private readonly int _timeoutSeconds;
    private readonly ILogger<GoogleTokenVerifier>? _logger;
    private readonly HttpClient _httpClient;

    public GoogleTokenVerifier(
        string? clientId = null,
        IReadOnlyList<string>? requiredScopes = null,
        int timeoutSeconds = 10,
        ILogger<GoogleTokenVerifier>? logger = null,
        HttpClient? httpClient = null)
    {
        _clientId = clientId;
        _requiredScopes = requiredScopes ?? Array.Empty<string>();
        _timeoutSeconds = timeoutSeconds;
        _logger = logger;
        _httpClient = httpClient ?? new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(timeoutSeconds)
        };
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
            // Use Google's tokeninfo endpoint to validate the token
            var response = await _httpClient.GetAsync(
                $"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={Uri.EscapeDataString(token)}",
                cancellationToken);

            if (!response.IsSuccessStatusCode)
            {
                _logger?.LogDebug("Google token verification failed: HTTP {StatusCode}", (int)response.StatusCode);
                return null;
            }

            var tokenInfo = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken);

            // Check if token is expired
            if (tokenInfo.TryGetProperty("expires_in", out var expiresInElement))
            {
                var expiresIn = expiresInElement.GetInt32();
                if (expiresIn <= 0)
                {
                    _logger?.LogDebug("Google token has expired");
                    return null;
                }
            }

            // Extract scopes
            var scopeString = tokenInfo.TryGetProperty("scope", out var scopeElement)
                ? scopeElement.GetString() ?? string.Empty
                : string.Empty;
            var tokenScopes = scopeString
                .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Select(s => s.Trim())
                .Where(s => !string.IsNullOrEmpty(s))
                .ToList();

            // Check required scopes
            if (_requiredScopes.Count > 0)
            {
                var tokenScopesSet = new HashSet<string>(tokenScopes, StringComparer.OrdinalIgnoreCase);
                var requiredScopesSet = new HashSet<string>(_requiredScopes, StringComparer.OrdinalIgnoreCase);
                if (!requiredScopesSet.IsSubsetOf(tokenScopesSet))
                {
                    _logger?.LogDebug(
                        "Google token missing required scopes. Has {TokenScopes}, needs {RequiredScopes}",
                        tokenScopesSet.Count,
                        requiredScopesSet.Count);
                    return null;
                }
            }

            // Get user info if we have the right scopes
            var userData = new Dictionary<string, object>();
            if (tokenScopes.Contains("openid") || tokenScopes.Contains("profile"))
            {
                try
                {
                    var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, "https://www.googleapis.com/oauth2/v2/userinfo");
                    userInfoRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                    var userInfoResponse = await _httpClient.SendAsync(userInfoRequest, cancellationToken);
                    if (userInfoResponse.IsSuccessStatusCode)
                    {
                        var userInfo = await userInfoResponse.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cancellationToken);
                        foreach (var prop in userInfo.EnumerateObject())
                        {
                            userData[prop.Name] = prop.Value.ValueKind == JsonValueKind.String
                                ? prop.Value.GetString() ?? string.Empty
                                : prop.Value.ToString();
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogDebug(ex, "Failed to fetch Google user info");
                }
            }

            // Calculate expiration time
            long? expiresAt = null;
            if (tokenInfo.TryGetProperty("expires_in", out var expiresInProp))
            {
                var expiresIn = expiresInProp.GetInt32();
                expiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + expiresIn;
            }

            var clientId = tokenInfo.TryGetProperty("audience", out var audienceElement)
                ? audienceElement.GetString() ?? "unknown"
                : "unknown";

            // Create AccessToken with Google user info
            var claims = new Dictionary<string, object>
            {
                ["sub"] = userData.GetValueOrDefault("id")?.ToString() ?? tokenInfo.TryGetProperty("user_id", out var userId) ? userId.GetString() ?? "unknown" : "unknown",
                ["email"] = userData.GetValueOrDefault("email")?.ToString() ?? string.Empty,
                ["name"] = userData.GetValueOrDefault("name")?.ToString() ?? string.Empty,
                ["picture"] = userData.GetValueOrDefault("picture")?.ToString() ?? string.Empty,
                ["given_name"] = userData.GetValueOrDefault("given_name")?.ToString() ?? string.Empty,
                ["family_name"] = userData.GetValueOrDefault("family_name")?.ToString() ?? string.Empty,
                ["locale"] = userData.GetValueOrDefault("locale")?.ToString() ?? string.Empty
            };

            _logger?.LogDebug("Google token verified successfully");
            return new AccessToken
            {
                Token = token,
                ClientId = clientId,
                Scopes = tokenScopes,
                ExpiresAt = expiresAt,
                Claims = claims
            };
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Google token verification error");
            return null;
        }
    }
}