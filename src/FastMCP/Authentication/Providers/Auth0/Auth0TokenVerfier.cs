using System;
using System.Collections.Generic;
using FastMCP.Authentication.Core;
using FastMCP.Authentication.Verification;
using Microsoft.Extensions.Logging;

namespace FastMCP.Authentication.Providers.Auth0;

/// <summary>
/// Token verifier for Auth0 OAuth tokens.
/// Auth0 supports JWT tokens via JWKS, so we use JWT verification.
/// </summary>
public class Auth0TokenVerifier : ITokenVerifier
{
    private readonly JwtTokenVerifier _jwtVerifier;

    public Auth0TokenVerifier(
        string configUrl,
        string? audience = null,
        IReadOnlyList<string>? requiredScopes = null,
        ILogger<Auth0TokenVerifier>? logger = null)
    {
        if (string.IsNullOrWhiteSpace(configUrl))
            throw new ArgumentException("Config URL cannot be null or empty", nameof(configUrl));

        var issuer = configUrl.TrimEnd('/');
        var jwksUri = $"{issuer}/.well-known/jwks.json";

        _jwtVerifier = new JwtTokenVerifier(
            jwksUri: jwksUri,
            issuer: issuer,
            audience: audience,
            requiredScopes: requiredScopes,
            logger: logger != null ? new LoggerAdapter<JwtTokenVerifier>(logger) : null);
    }

    public IReadOnlyList<string> RequiredScopes => _jwtVerifier.RequiredScopes;

    public Task<AccessToken?> VerifyTokenAsync(string token, CancellationToken cancellationToken = default)
    {
        return _jwtVerifier.VerifyTokenAsync(token, cancellationToken);
    }

    private class LoggerAdapter<T> : ILogger<T>
    {
        private readonly ILogger _logger;
        public LoggerAdapter(ILogger logger) => _logger = logger;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => _logger.BeginScope(state);
        public bool IsEnabled(LogLevel logLevel) => _logger.IsEnabled(logLevel);
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            => _logger.Log(logLevel, eventId, state, exception, formatter);
    }
}