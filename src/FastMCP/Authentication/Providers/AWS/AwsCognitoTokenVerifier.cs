using System;
using System.Collections.Generic;
using FastMCP.Authentication.Core;
using FastMCP.Authentication.Verification;
using Microsoft.Extensions.Logging;

namespace FastMCP.Authentication.Providers.AWS;

/// <summary>
/// Token verifier for AWS Cognito OAuth tokens.
/// AWS Cognito uses JWT tokens with JWKS for validation.
/// </summary>
public class AwsCognitoTokenVerifier : ITokenVerifier
{
    private readonly JwtTokenVerifier _jwtVerifier;

    public AwsCognitoTokenVerifier(
        string userPoolId,
        string awsRegion = "us-east-1",
        string? audience = null,
        IReadOnlyList<string>? requiredScopes = null,
        ILogger<AwsCognitoTokenVerifier>? logger = null)
    {
        if (string.IsNullOrWhiteSpace(userPoolId))
            throw new ArgumentException("User Pool ID cannot be null or empty", nameof(userPoolId));

        var issuer = $"https://cognito-idp.{awsRegion}.amazonaws.com/{userPoolId}";
        var jwksUri = $"{issuer}/.well-known/jwks.json";

        _jwtVerifier = new JwtTokenVerifier(
            jwksUri: jwksUri,
            issuer: issuer,
            audience: audience,
            requiredScopes: requiredScopes ?? new[] { "openid" },
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