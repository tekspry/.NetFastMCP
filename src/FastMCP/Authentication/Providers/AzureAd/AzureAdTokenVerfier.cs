using System;
using System.Collections.Generic;
using FastMCP.Authentication.Core;
using FastMCP.Authentication.Verification;
using Microsoft.Extensions.Logging;

namespace FastMCP.Authentication.Providers.AzureAd;

/// <summary>
/// Token verifier for Azure AD (Microsoft Entra) OAuth tokens.
/// Azure AD uses JWT tokens with JWKS for validation.
/// </summary>
public class AzureAdTokenVerifier : ITokenVerifier
{
    private readonly JwtTokenVerifier _jwtVerifier;

    public AzureAdTokenVerifier(
        string tenantId,
        string? clientId = null,
        IReadOnlyList<string>? requiredScopes = null,
        string baseAuthority = "login.microsoftonline.com",
        ILogger<AzureAdTokenVerifier>? logger = null)
    {
        if (string.IsNullOrWhiteSpace(tenantId))
            throw new ArgumentException("Tenant ID cannot be null or empty", nameof(tenantId));

        var issuer = $"https://{baseAuthority}/{tenantId}/v2.0";
        var jwksUri = $"https://{baseAuthority}/{tenantId}/discovery/v2.0/keys";

        _jwtVerifier = new JwtTokenVerifier(
            jwksUri: jwksUri,
            issuer: issuer,
            audience: clientId,
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