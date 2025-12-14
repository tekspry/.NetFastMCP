using FastMCP.Authentication.Core;
using FastMCP.Authentication.Middleware;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace FastMCP.Authentication.Extensions;

/// <summary>
/// Extension methods for registering token verifier-based authentication.
/// </summary>
public static class AuthenticationBuilderExtensions
{
    /// <summary>
    /// Adds token verifier authentication using the specified token verifier instance.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="scheme">The authentication scheme name.</param>
    /// <param name="tokenVerifier">The token verifier instance to use.</param>
    /// <param name="configureOptions">Optional configuration action.</param>
    /// <returns>The authentication builder for chaining.</returns>
    public static AuthenticationBuilder AddTokenVerifier(
        this AuthenticationBuilder builder,
        string scheme,
        ITokenVerifier tokenVerifier,
        Action<TokenVerifierAuthenticationOptions>? configureOptions = null)
    {
        if (builder == null)
            throw new ArgumentNullException(nameof(builder));
        if (string.IsNullOrEmpty(scheme))
            throw new ArgumentException("Scheme name cannot be null or empty", nameof(scheme));
        if (tokenVerifier == null)
            throw new ArgumentNullException(nameof(tokenVerifier));

        // Register the token verifier as a singleton
        builder.Services.TryAddSingleton(tokenVerifier);

        // Add the authentication handler
        return builder.AddScheme<TokenVerifierAuthenticationOptions, TokenVerifierAuthenticationHandler>(
            scheme,
            configureOptions);
    }

    /// <summary>
    /// Adds token verifier authentication using a token verifier registered in DI.
    /// </summary>
    /// <typeparam name="TTokenVerifier">The type of token verifier to use.</typeparam>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="scheme">The authentication scheme name.</param>
    /// <param name="configureOptions">Optional configuration action.</param>
    /// <returns>The authentication builder for chaining.</returns>
    public static AuthenticationBuilder AddTokenVerifier<TTokenVerifier>(
        this AuthenticationBuilder builder,
        string scheme,
        Action<TokenVerifierAuthenticationOptions>? configureOptions = null)
        where TTokenVerifier : class, ITokenVerifier
    {
        if (builder == null)
            throw new ArgumentNullException(nameof(builder));
        if (string.IsNullOrEmpty(scheme))
            throw new ArgumentException("Scheme name cannot be null or empty", nameof(scheme));

        // Register the token verifier
        builder.Services.TryAddSingleton<TTokenVerifier>();

        // Add the authentication handler
        return builder.AddScheme<TokenVerifierAuthenticationOptions, TokenVerifierAuthenticationHandler>(
            scheme,
            configureOptions);
    }
}