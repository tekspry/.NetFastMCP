using System;
using System.Collections.Generic;
using FastMCP.Authentication.Core;
using FastMCP.Authentication.Verification;
using Microsoft.Extensions.Logging;

namespace FastMCP.Authentication.Providers.Okta;

/// <summary>
/// Token verifier for Okta OAuth tokens.
/// Okta supports both JWT tokens (via JWKS) and opaque tokens (via introspection).
/// This implementation supports both approaches.
/// </summary>
public class OktaTokenVerifier : ITokenVerifier
{
    private readonly ITokenVerifier _innerVerifier;

    /// <summary>
    /// Creates an Okta token verifier using JWT verification (recommended for access tokens).
    /// </summary>
    public OktaTokenVerifier(
        string oktaDomain,
        string? audience = null,
        IReadOnlyList<string>? requiredScopes = null,
        ILogger<OktaTokenVerifier>? logger = null)
    {
        if (string.IsNullOrWhiteSpace(oktaDomain))
            throw new ArgumentException("Okta domain cannot be null or empty", nameof(oktaDomain));

        var issuer = oktaDomain.TrimEnd('/');
        var jwksUri = $"{issuer}/oauth2/default/v1/keys";
        
        _innerVerifier = new JwtTokenVerifier(
            jwksUri: jwksUri,
            issuer: issuer,
            audience: audience,
            requiredScopes: requiredScopes,
            logger: logger != null ? new LoggerAdapter<JwtTokenVerifier>(logger) : null);
    }

    /// <summary>
    /// Creates an Okta token verifier using token introspection (for opaque tokens).
    /// </summary>
    public OktaTokenVerifier(
        string oktaDomain,
        string clientId,
        string clientSecret,
        string? audience = null,
        IReadOnlyList<string>? requiredScopes = null,
        int timeoutSeconds = 10,
        ILogger<OktaTokenVerifier>? logger = null,
        bool useIntrospection = false)
    {
        if (string.IsNullOrWhiteSpace(oktaDomain))
            throw new ArgumentException("Okta domain cannot be null or empty", nameof(oktaDomain));

        if (useIntrospection)
        {
            var introspectionUrl = $"{oktaDomain.TrimEnd('/')}/oauth2/default/v1/introspect";
            _innerVerifier = new IntrospectionTokenVerifier(
                introspectionUrl: introspectionUrl,
                clientId: clientId,
                clientSecret: clientSecret,
                timeoutSeconds: timeoutSeconds,
                requiredScopes: requiredScopes,
                logger: logger != null ? new LoggerAdapter<IntrospectionTokenVerifier>(logger) : null);
        }
        else
        {
            var issuer = oktaDomain.TrimEnd('/');
            var jwksUri = $"{issuer}/oauth2/default/v1/keys";
            _innerVerifier = new JwtTokenVerifier(
                jwksUri: jwksUri,
                issuer: issuer,
                audience: audience ?? clientId,
                requiredScopes: requiredScopes,
                logger: logger != null ? new LoggerAdapter<JwtTokenVerifier>(logger) : null);
        }
    }

    public IReadOnlyList<string> RequiredScopes => _innerVerifier.RequiredScopes;

    public Task<AccessToken?> VerifyTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        return _innerVerifier.VerifyTokenAsync(token, cancellationToken);
    }

    // Logger adapter to convert between logger types
    private class LoggerAdapter<T> : ILogger<T>
    {
        private readonly ILogger _logger;

        public LoggerAdapter(ILogger logger)
        {
            _logger = logger;
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => _logger.BeginScope(state);
        public bool IsEnabled(LogLevel logLevel) => _logger.IsEnabled(logLevel);
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => _logger.Log(logLevel, eventId, state, exception, formatter);
    }
}