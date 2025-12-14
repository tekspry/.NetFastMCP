using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;
using FastMCP.Authentication.Core;
using FastMCP.Authentication.Verification;
using Microsoft.Extensions.Logging;

namespace FastMCP.Authentication.Proxy;

/// <summary>
/// OAuth provider that presents a DCR-compliant interface while proxying to non-DCR IDPs.
/// 
/// This proxy bridges the gap between MCP clients' expectation of Dynamic Client Registration
/// and upstream providers (Google, GitHub, Azure AD, etc.) that require pre-registered apps.
/// 
/// Key features:
/// - Accepts DCR registration requests from MCP clients
/// - Uses fixed upstream credentials for actual OAuth flows
/// - Handles dynamic redirect URIs from clients
/// - Proxies authorization and token endpoints
/// - Manages state and code mapping
/// </summary>
public class OAuthProxy : IMcpAuthProvider
{
    private readonly OAuthProxyOptions _options;
    private readonly ITokenVerifier _tokenVerifier;
    private readonly IClientStore _clientStore;
    private readonly ILogger<OAuthProxy>? _logger;
    private readonly HttpClient _httpClient;
    private readonly Dictionary<string, OAuthTransaction> _transactions = new();
    private readonly Dictionary<string, ClientCode> _clientCodes = new();

    public OAuthProxy(
        OAuthProxyOptions options,
        ITokenVerifier tokenVerifier,
        IClientStore? clientStore = null,
        ILogger<OAuthProxy>? logger = null,
        HttpClient? httpClient = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _tokenVerifier = tokenVerifier ?? throw new ArgumentNullException(nameof(tokenVerifier));
        _clientStore = clientStore ?? new InMemoryClientStore();
        _logger = logger;
        _httpClient = httpClient ?? new HttpClient();
    }

    public string? BaseUrl => _options.BaseUrl;
    public string SchemeName => "OAuthProxy";
    public IReadOnlyList<string> RequiredScopes => _tokenVerifier.RequiredScopes;

    /// <summary>
    /// Registers a new OAuth client (DCR).
    /// </summary>
    public async Task<OAuthClientRegistration> RegisterClientAsync(OAuthClientRegistration clientInfo)
    {
        if (string.IsNullOrEmpty(clientInfo.ClientId))
        {
            // Generate client ID if not provided
            clientInfo.ClientId = GenerateClientId();
        }

        if (string.IsNullOrEmpty(clientInfo.ClientSecret))
        {
            // Generate client secret if not provided
            clientInfo.ClientSecret = GenerateClientSecret();
        }

        // Set allowed redirect URI patterns from options
        clientInfo.AllowedRedirectUriPatterns = _options.AllowedClientRedirectUris;

        // Store the client
        await _clientStore.StoreClientAsync(clientInfo.ClientId, clientInfo);

        _logger?.LogInformation(
            "Registered OAuth client {ClientId} with {RedirectUriCount} redirect URIs",
            clientInfo.ClientId,
            clientInfo.RedirectUris.Count);

        return clientInfo;
    }

    /// <summary>
    /// Gets a registered client by ID.
    /// </summary>
    public async Task<OAuthClientRegistration?> GetClientAsync(string clientId)
    {
        return await _clientStore.GetClientAsync(clientId);
    }

    /// <summary>
    /// Initiates the authorization flow by redirecting to upstream provider.
    /// </summary>
    public string GetAuthorizationUrl(
        string clientId,
        string redirectUri,
        string state,
        string? codeChallenge = null,
        string codeChallengeMethod = "S256",
        IReadOnlyList<string>? scopes = null)
    {
        // Validate client
        var client = _clientStore.GetClientAsync(clientId).GetAwaiter().GetResult();
        if (client == null)
        {
            throw new InvalidOperationException($"Client {clientId} is not registered");
        }

        // Validate redirect URI
        if (!ValidateRedirectUri(redirectUri, client))
        {
            throw new InvalidOperationException($"Redirect URI {redirectUri} is not allowed for client {clientId}");
        }

        // Create transaction
        var txnId = GenerateTransactionId();
        var transaction = new OAuthTransaction
        {
            TransactionId = txnId,
            ClientId = clientId,
            ClientRedirectUri = redirectUri,
            ClientState = state,
            CodeChallenge = codeChallenge,
            CodeChallengeMethod = codeChallengeMethod,
            Scopes = scopes?.ToList() ?? new List<string>(),
            CreatedAt = DateTime.UtcNow
        };
        _transactions[txnId] = transaction;

        // Build upstream authorization URL
        var proxyRedirectUri = $"{_options.BaseUrl.TrimEnd('/')}{_options.RedirectPath}";
        var upstreamScopes = scopes ?? _tokenVerifier.RequiredScopes;

        var queryParams = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = _options.UpstreamClientId,
            ["redirect_uri"] = proxyRedirectUri,
            ["scope"] = string.Join(" ", upstreamScopes),
            ["state"] = txnId // Use transaction ID as state with upstream
        };

        if (!string.IsNullOrEmpty(codeChallenge) && _options.ForwardPkce)
        {
            queryParams["code_challenge"] = codeChallenge;
            queryParams["code_challenge_method"] = codeChallengeMethod;
        }

        // Add extra authorize parameters if configured
        // (This would be extended based on provider-specific needs)

        var queryString = string.Join("&", queryParams.Select(kvp => 
            $"{HttpUtility.UrlEncode(kvp.Key)}={HttpUtility.UrlEncode(kvp.Value)}"));

        var authUrl = $"{_options.UpstreamAuthorizationEndpoint}?{queryString}";

        _logger?.LogDebug(
            "Generated authorization URL for client {ClientId}, transaction {TxnId}",
            clientId,
            txnId);

        return authUrl;
    }

    /// <summary>
    /// Handles the callback from upstream provider and exchanges code for tokens.
    /// </summary>
    public async Task<OAuthTokenResponse> HandleCallbackAsync(
        string code,
        string state,
        string? codeVerifier = null)
    {
        // Find transaction by state (which is our transaction ID)
        if (!_transactions.TryGetValue(state, out var transaction))
        {
            throw new InvalidOperationException("Invalid or expired transaction");
        }

        // Add this check:
        if (DateTime.UtcNow - transaction.CreatedAt > TimeSpan.FromMinutes(10))
        {
            _transactions.Remove(state);
            throw new InvalidOperationException("Transaction has expired");
        }

        // Exchange code with upstream provider
        var tokenResponse = await ExchangeCodeWithUpstreamAsync(code, transaction, codeVerifier);

        // Generate a new authorization code for the client
        var clientCode = GenerateClientCode();
        var clientCodeData = new ClientCode
        {
            Code = clientCode,
            ClientId = transaction.ClientId,
            RedirectUri = transaction.ClientRedirectUri,
            CodeChallenge = transaction.CodeChallenge,
            CodeChallengeMethod = transaction.CodeChallengeMethod,
            Scopes = transaction.Scopes,
            UpstreamTokens = tokenResponse,
            ExpiresAt = DateTime.UtcNow.AddMinutes(5), // Short expiry for security
            CreatedAt = DateTime.UtcNow
        };
        _clientCodes[clientCode] = clientCodeData;

        // Clean up transaction
        _transactions.Remove(state);

        _logger?.LogDebug(
            "Exchanged upstream code for client code, client {ClientId}",
            transaction.ClientId);

        // Return redirect URL with new code
        var redirectUrl = $"{transaction.ClientRedirectUri}?code={HttpUtility.UrlEncode(clientCode)}&state={HttpUtility.UrlEncode(transaction.ClientState)}";

        return new OAuthTokenResponse
        {
            RedirectUri = redirectUrl,
            ClientCode = clientCode
        };
    }

    /// <summary>
    /// Exchanges client authorization code for access token.
    /// </summary>
    public async Task<TokenExchangeResponse> ExchangeCodeForTokenAsync(
        string code,
        string redirectUri,
        string? codeVerifier = null)
    {
        if (!_clientCodes.TryGetValue(code, out var clientCode))
        {
            throw new InvalidOperationException("Invalid or expired authorization code");
        }

        // Validate redirect URI
        if (clientCode.RedirectUri != redirectUri)
        {
            throw new InvalidOperationException("Redirect URI mismatch");
        }

        // Validate PKCE if present
        if (!string.IsNullOrEmpty(clientCode.CodeChallenge))
        {
            if (string.IsNullOrEmpty(codeVerifier))
            {
                throw new InvalidOperationException("Code verifier is required");
            }

            var expectedChallenge = ComputeCodeChallenge(codeVerifier, clientCode.CodeChallengeMethod);
            if (expectedChallenge != clientCode.CodeChallenge)
            {
                throw new InvalidOperationException("Invalid code verifier");
            }
        }

        // Check expiration
        if (clientCode.ExpiresAt < DateTime.UtcNow)
        {
            _clientCodes.Remove(code);
            throw new InvalidOperationException("Authorization code has expired");
        }

        // Return the upstream tokens
        var response = new TokenExchangeResponse
        {
            AccessToken = clientCode.UpstreamTokens.AccessToken,
            TokenType = clientCode.UpstreamTokens.TokenType ?? "Bearer",
            ExpiresIn = clientCode.UpstreamTokens.ExpiresIn,
            RefreshToken = clientCode.UpstreamTokens.RefreshToken,
            Scope = string.Join(" ", clientCode.Scopes)
        };

        // Clean up one-time use code
        _clientCodes.Remove(code);

        _logger?.LogDebug(
            "Exchanged client code for tokens, client {ClientId}",
            clientCode.ClientId);

        return response;
    }

    /// <summary>
    /// Refreshes an access token using refresh token.
    /// </summary>
    public async Task<TokenExchangeResponse> RefreshTokenAsync(string refreshToken)
    {
        // Exchange refresh token with upstream provider
        var tokenResponse = await RefreshTokenWithUpstreamAsync(refreshToken);

        return new TokenExchangeResponse
        {
            AccessToken = tokenResponse.AccessToken,
            TokenType = tokenResponse.TokenType ?? "Bearer",
            ExpiresIn = tokenResponse.ExpiresIn,
            RefreshToken = tokenResponse.RefreshToken ?? refreshToken, // Use new refresh token if provided
            Scope = tokenResponse.Scope
        };
    }

    public Task<AccessToken?> VerifyTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        return _tokenVerifier.VerifyTokenAsync(token, cancellationToken);
    }

    public async Task RevokeTokenAsync(string token, string? tokenTypeHint = null)
    {
        // For in-memory storage, we can just remove it
        // For production, you'd forward to upstream provider
        // Implementation depends on your storage backend
        
        // Example for upstream providers:
        if (!string.IsNullOrEmpty(_options.UpstreamRevocationEndpoint))
        {
            var tokenRequest = new Dictionary<string, string>
            {
                ["token"] = token,
                ["client_id"] = _options.UpstreamClientId,
                ["client_secret"] = _options.UpstreamClientSecret
            };

            if (!string.IsNullOrEmpty(tokenTypeHint))
            {
                tokenRequest["token_type_hint"] = tokenTypeHint;
            }

            var content = new FormUrlEncodedContent(tokenRequest);
            var response = await _httpClient.PostAsync(_options.UpstreamRevocationEndpoint, content);
            
            // RFC 7009 requires 200 OK even if token doesn't exist
            // So we don't need to check response.IsSuccessStatusCode
        }
}

    // Private helper methods

    private async Task<UpstreamTokenResponse> ExchangeCodeWithUpstreamAsync(
    string code,
    OAuthTransaction transaction,
    string? codeVerifier)
    {
        var tokenRequest = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = $"{_options.BaseUrl.TrimEnd('/')}{_options.RedirectPath}",
            ["client_id"] = _options.UpstreamClientId,
            ["client_secret"] = _options.UpstreamClientSecret
        };

        if (!string.IsNullOrEmpty(codeVerifier) && _options.ForwardPkce)
        {
            tokenRequest["code_verifier"] = codeVerifier;
        }

        try
        {
            var content = new FormUrlEncodedContent(tokenRequest);
            var response = await _httpClient.PostAsync(_options.UpstreamTokenEndpoint, content);

            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            var tokenData = JsonSerializer.Deserialize<JsonElement>(json);

            return new UpstreamTokenResponse
            {
                AccessToken = tokenData.TryGetProperty("access_token", out var accessToken) 
                    ? accessToken.GetString() ?? string.Empty
                    : throw new InvalidOperationException("Missing access_token in response"),
                TokenType = tokenData.TryGetProperty("token_type", out var tokenType)
                    ? tokenType.GetString()
                    : "Bearer",
                ExpiresIn = tokenData.TryGetProperty("expires_in", out var expiresIn)
                    ? expiresIn.GetInt32()
                    : null,
                RefreshToken = tokenData.TryGetProperty("refresh_token", out var refreshToken)
                    ? refreshToken.GetString()
                    : null,
                Scope = tokenData.TryGetProperty("scope", out var scope)
                    ? scope.GetString()
                    : null
            };
        }
        catch (HttpRequestException ex)
        {
            _logger?.LogError(ex, "Failed to exchange code with upstream provider");
            throw new InvalidOperationException("Failed to exchange code with upstream provider", ex);
        }
}

    private async Task<UpstreamTokenResponse> RefreshTokenWithUpstreamAsync(string refreshToken)
    {
        var tokenRequest = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = _options.UpstreamClientId,
            ["client_secret"] = _options.UpstreamClientSecret
        };

        try
        {
            var content = new FormUrlEncodedContent(tokenRequest);
            var response = await _httpClient.PostAsync(_options.UpstreamTokenEndpoint, content);

            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            var tokenData = JsonSerializer.Deserialize<JsonElement>(json);

            return new UpstreamTokenResponse
            {
                AccessToken = tokenData.TryGetProperty("access_token", out var accessToken)
                    ? accessToken.GetString() ?? string.Empty
                    : throw new InvalidOperationException("Missing access_token in response"),
                TokenType = tokenData.TryGetProperty("token_type", out var tokenType)
                    ? tokenType.GetString()
                    : "Bearer",
                ExpiresIn = tokenData.TryGetProperty("expires_in", out var expiresIn)
                    ? expiresIn.GetInt32()
                    : null,
                RefreshToken = tokenData.TryGetProperty("refresh_token", out var refreshTokenNew)
                    ? refreshTokenNew.GetString()
                    : refreshToken,  // Use original if not provided
                Scope = tokenData.TryGetProperty("scope", out var scope)
                    ? scope.GetString()
                    : null
            };
        }
        catch (HttpRequestException ex)
        {
            _logger?.LogError(ex, "Failed to refresh token with upstream provider");
            throw new InvalidOperationException("Failed to refresh token", ex);
        }
    }

    private bool ValidateRedirectUri(string redirectUri, OAuthClientRegistration client)
    {
        // If client has specific redirect URIs, validate against them
        if (client.RedirectUris.Count > 0)
        {
            if (client.RedirectUris.Contains(redirectUri))
            {
                return true;
            }
        }

        // Check against allowed patterns if configured
        var patterns = client.AllowedRedirectUriPatterns ?? _options.AllowedClientRedirectUris;
        
        if (patterns == null || patterns.Count == 0)
        {
            // No patterns means no restrictions (not recommended for production)
            return true;
        }

        // Check if redirect URI matches any allowed pattern
        foreach (var pattern in patterns)
        {
            if (MatchesPattern(redirectUri, pattern))
            {
                return true;
            }
        }

        return false;
    }

    private bool MatchesPattern(string uri, string pattern)
    {
        // Convert glob pattern to regex
        // Supports wildcards: * (any characters), ? (single character)
        var regexPattern = Regex.Escape(pattern)
            .Replace("\\*", ".*")      // * -> .*
            .Replace("\\?", ".");       // ? -> .
        
        var regex = new Regex($"^{regexPattern}$", RegexOptions.IgnoreCase);
        return regex.IsMatch(uri);
    }

    private string GenerateClientId() => Guid.NewGuid().ToString("N");
    private string GenerateClientSecret() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    private string GenerateTransactionId() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)).TrimEnd('=');
    private string GenerateClientCode() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)).TrimEnd('=');

    private string ComputeCodeChallenge(string codeVerifier, string method)
    {
        if (method == "S256")
        {
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
            var base64 = Convert.ToBase64String(hash);
            return base64.Replace("+", "-").Replace("/", "_").TrimEnd('=');
        }
        else if (method == "plain")
        {
            return codeVerifier;
        }
        else
        {
            throw new InvalidOperationException($"Unsupported PKCE method: {method}");
        }
    }

    // Supporting classes

    private class OAuthTransaction
    {
        public string TransactionId { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string ClientRedirectUri { get; set; } = string.Empty;
        public string ClientState { get; set; } = string.Empty;
        public string? CodeChallenge { get; set; }
        public string CodeChallengeMethod { get; set; } = "S256";
        public List<string> Scopes { get; set; } = new();
        public DateTime CreatedAt { get; set; }
    }

    private class ClientCode
    {
        public string Code { get; set; } = string.Empty;
        public string ClientId { get; set; } = string.Empty;
        public string RedirectUri { get; set; } = string.Empty;
        public string? CodeChallenge { get; set; }
        public string CodeChallengeMethod { get; set; } = "S256";
        public List<string> Scopes { get; set; } = new();
        public UpstreamTokenResponse UpstreamTokens { get; set; } = new();
        public DateTime ExpiresAt { get; set; }
        public DateTime CreatedAt { get; set; }
    }

    private class UpstreamTokenResponse
    {
        public string AccessToken { get; set; } = string.Empty;
        public string? TokenType { get; set; }
        public int? ExpiresIn { get; set; }
        public string? RefreshToken { get; set; }
        public string? Scope { get; set; }
    }

    public class OAuthTokenResponse
    {
        public string RedirectUri { get; set; } = string.Empty;
        public string ClientCode { get; set; } = string.Empty;
    }

    public class TokenExchangeResponse
    {
        public string AccessToken { get; set; } = string.Empty;
        public string TokenType { get; set; } = "Bearer";
        public int? ExpiresIn { get; set; }
        public string? RefreshToken { get; set; }
        public string? Scope { get; set; }
    }
}