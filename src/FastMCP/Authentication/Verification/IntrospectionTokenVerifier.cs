using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using FastMCP.Authentication.Core;
using Microsoft.Extensions.Logging;

namespace FastMCP.Authentication.Verification;

/// <summary>
/// OAuth 2.0 Token Introspection verifier (RFC 7662).
/// This verifier validates opaque tokens by calling an OAuth 2.0 token introspection
/// endpoint. Unlike JWT verification which is stateless, token introspection requires
/// a network call to the authorization server for each token validation.
/// 
/// Use this when:
/// - Your authorization server issues opaque (non-JWT) tokens
/// - You need to validate tokens from Auth0, Okta, Keycloak, or other OAuth servers
/// - Your tokens require real-time revocation checking
/// - Your authorization server supports RFC 7662 introspection
/// </summary>
public class IntrospectionTokenVerifier : ITokenVerifier
{
    private readonly string _introspectionUrl;
    private readonly string _clientId;
    private readonly string _clientSecret;
    private readonly int _timeoutSeconds;
    private readonly IReadOnlyList<string> _requiredScopes;
    private readonly ILogger<IntrospectionTokenVerifier>? _logger;
    private readonly HttpClient _httpClient;

    /// <summary>
    /// Initializes a new instance of the IntrospectionTokenVerifier.
    /// </summary>
    /// <param name="introspectionUrl">URL of the OAuth 2.0 token introspection endpoint.</param>
    /// <param name="clientId">OAuth client ID for authenticating to the introspection endpoint.</param>
    /// <param name="clientSecret">OAuth client secret for authenticating to the introspection endpoint.</param>
    /// <param name="timeoutSeconds">HTTP request timeout in seconds (default: 10).</param>
    /// <param name="requiredScopes">Required scopes for all tokens (optional).</param>
    /// <param name="logger">Optional logger for diagnostics.</param>
    /// <param name="httpClient">Optional HttpClient instance. If not provided, a new instance will be created.</param>
    public IntrospectionTokenVerifier(
        string introspectionUrl,
        string clientId,
        string clientSecret,
        int timeoutSeconds = 10,
        IReadOnlyList<string>? requiredScopes = null,
        ILogger<IntrospectionTokenVerifier>? logger = null,
        HttpClient? httpClient = null)
    {
        _introspectionUrl = introspectionUrl ?? throw new ArgumentNullException(nameof(introspectionUrl));
        _clientId = clientId ?? throw new ArgumentNullException(nameof(clientId));
        _clientSecret = clientSecret ?? throw new ArgumentNullException(nameof(clientSecret));
        _timeoutSeconds = timeoutSeconds;
        _requiredScopes = requiredScopes ?? Array.Empty<string>();
        _logger = logger;
        _httpClient = httpClient ?? new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(timeoutSeconds)
        };
    }

    /// <inheritdoc/>
    public IReadOnlyList<string> RequiredScopes => _requiredScopes;

    /// <inheritdoc/>
    public async Task<AccessToken?> VerifyTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            _logger?.LogDebug("Token verification failed: token is null or empty");
            return null;
        }

        try
        {
            // Create HTTP Basic Auth header
            var authHeader = CreateBasicAuthHeader();

            // Prepare introspection request per RFC 7662
            var requestContent = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("token", token),
                new KeyValuePair<string, string>("token_type_hint", "access_token")
            });

            var request = new HttpRequestMessage(HttpMethod.Post, _introspectionUrl)
            {
                Content = requestContent,
                Headers = { Authorization = new AuthenticationHeaderValue("Basic", authHeader) }
            };

            var response = await _httpClient.SendAsync(request, cancellationToken);

            // Check for HTTP errors
            if (!response.IsSuccessStatusCode)
            {
                _logger?.LogDebug(
                    "Token introspection failed: HTTP {StatusCode} - {ReasonPhrase}",
                    (int)response.StatusCode,
                    response.ReasonPhrase);
                return null;
            }

            var json = await response.Content.ReadAsStringAsync(cancellationToken);
            var introspectionData = JsonSerializer.Deserialize<JsonElement>(json);

            // Check if token is active (required field per RFC 7662)
            if (!introspectionData.TryGetProperty("active", out var activeElement) ||
                !activeElement.GetBoolean())
            {
                _logger?.LogDebug("Token introspection returned active=false");
                return null;
            }

            // Extract client_id
            var clientId = introspectionData.TryGetProperty("client_id", out var clientIdElement)
                ? clientIdElement.GetString()
                : introspectionData.TryGetProperty("sub", out var subElement)
                    ? subElement.GetString()
                    : "unknown";

            // Extract expiration time
            long? expiresAt = null;
            if (introspectionData.TryGetProperty("exp", out var expElement) &&
                expElement.ValueKind == JsonValueKind.Number)
            {
                var exp = expElement.GetInt64();
                // Validate expiration (belt and suspenders - server should set active=false)
                var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                if (exp < now)
                {
                    _logger?.LogDebug("Token validation failed: expired token for client {ClientId}", clientId);
                    return null;
                }
                expiresAt = exp;
            }

            // Extract scopes
            var scopes = ExtractScopes(introspectionData);

            // Check required scopes
            if (_requiredScopes.Count > 0)
            {
                var tokenScopes = new HashSet<string>(scopes, StringComparer.OrdinalIgnoreCase);
                var required = new HashSet<string>(_requiredScopes, StringComparer.OrdinalIgnoreCase);
                
                if (!required.IsSubsetOf(tokenScopes))
                {
                    _logger?.LogDebug(
                        "Token missing required scopes. Has: {TokenScopes}, Required: {RequiredScopes}",
                        string.Join(", ", tokenScopes),
                        string.Join(", ", required));
                    return null;
                }
            }

            // Extract all claims from introspection response
            var claims = new Dictionary<string, object>();
            foreach (var property in introspectionData.EnumerateObject())
            {
                claims[property.Name] = property.Value.ValueKind switch
                {
                    JsonValueKind.String => property.Value.GetString() ?? string.Empty,
                    JsonValueKind.Number => property.Value.GetInt64(),
                    JsonValueKind.True => true,
                    JsonValueKind.False => false,
                    JsonValueKind.Array => property.Value.EnumerateArray()
                        .Select(e => e.ValueKind == JsonValueKind.String ? e.GetString() : e.ToString())
                        .Where(s => s != null)
                        .ToList()!,
                    _ => property.Value.ToString()
                };
            }

            _logger?.LogDebug("Token introspection successful for client {ClientId}", clientId);

            return new AccessToken
            {
                Token = token,
                ClientId = clientId ?? "unknown",
                Scopes = scopes,
                ExpiresAt = expiresAt,
                Claims = claims
            };
        }
        catch (TaskCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            _logger?.LogDebug("Token introspection was cancelled");
            return null;
        }
        catch (TaskCanceledException)
        {
            _logger?.LogDebug("Token introspection timed out after {TimeoutSeconds} seconds", _timeoutSeconds);
            return null;
        }
        catch (HttpRequestException ex)
        {
            _logger?.LogError(ex, "Token introspection request failed");
            return null;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Unexpected error during token introspection");
            return null;
        }
    }

    private string CreateBasicAuthHeader()
    {
        var credentials = $"{_clientId}:{_clientSecret}";
        var bytes = Encoding.UTF8.GetBytes(credentials);
        return Convert.ToBase64String(bytes);
    }

    private IReadOnlyList<string> ExtractScopes(JsonElement introspectionData)
    {
        // RFC 7662 allows scopes to be returned as either:
        // - A space-separated string in the 'scope' field
        // - An array of strings in the 'scope' field (less common but valid)
        
        if (!introspectionData.TryGetProperty("scope", out var scopeElement))
            return Array.Empty<string>();

        // Handle string (space-separated) scopes
        if (scopeElement.ValueKind == JsonValueKind.String)
        {
            var scopeString = scopeElement.GetString();
            if (string.IsNullOrWhiteSpace(scopeString))
                return Array.Empty<string>();

            return scopeString
                .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Select(s => s.Trim())
                .Where(s => !string.IsNullOrEmpty(s))
                .ToList();
        }

        // Handle array of scopes
        if (scopeElement.ValueKind == JsonValueKind.Array)
        {
            return scopeElement.EnumerateArray()
                .Select(e => e.GetString())
                .Where(s => !string.IsNullOrEmpty(s))
                .ToList()!;
        }

        return Array.Empty<string>();
    }
}