using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using System.Web;
using FastMCP.Authentication.Core;
using FastMCP.Authentication.Proxy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace FastMCP.Authentication.Proxy;

/// <summary>
/// Extension methods for registering OAuth Proxy endpoints (DCR, authorization, token).
/// </summary>
public static class OAuthProxyEndpoints
{
    /// <summary>
    /// Maps OAuth Proxy endpoints including DCR, authorization, and token endpoints.
    /// </summary>
    public static void MapOAuthProxyEndpoints(this WebApplication app, OAuthProxy proxy)
    {
        // Dynamic Client Registration endpoint (RFC 7591)
        app.MapPost("/oauth/register", async (HttpContext context) =>
        {
            var registrationRequest = await JsonSerializer.DeserializeAsync<OAuthClientRegistrationRequest>(
                context.Request.Body,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (registrationRequest == null)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_request" });
                return;
            }

            try
            {
                var client = new OAuthClientRegistration
                {
                    ClientId = registrationRequest.ClientId ?? Guid.NewGuid().ToString("N"),
                    ClientSecret = registrationRequest.ClientSecret ?? Convert.ToBase64String(
                        System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)),
                    RedirectUris = registrationRequest.RedirectUris ?? Array.Empty<string>(),
                    GrantTypes = registrationRequest.GrantTypes ?? new[] { "authorization_code", "refresh_token" },
                    Scope = registrationRequest.Scope ?? string.Empty,
                    TokenEndpointAuthMethod = registrationRequest.TokenEndpointAuthMethod ?? "none",
                    ClientName = registrationRequest.ClientName
                };

                var registeredClient = await proxy.RegisterClientAsync(client);

                context.Response.StatusCode = 201;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new
                {
                    client_id = registeredClient.ClientId,
                    client_secret = registeredClient.ClientSecret,
                    redirect_uris = registeredClient.RedirectUris,
                    grant_types = registeredClient.GrantTypes,
                    scope = registeredClient.Scope,
                    token_endpoint_auth_method = registeredClient.TokenEndpointAuthMethod,
                    client_name = registeredClient.ClientName
                });
            }
            catch (Exception ex)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_request", error_description = ex.Message });
            }
        })
        .WithName("OAuthClientRegistration")
        .AllowAnonymous();

        // Authorization endpoint
        app.MapGet("/oauth/authorize", async (HttpContext context) =>
        {
            var clientId = context.Request.Query["client_id"].ToString();
            var redirectUri = context.Request.Query["redirect_uri"].ToString();
            var state = context.Request.Query["state"].ToString();
            var codeChallenge = context.Request.Query["code_challenge"].ToString();
            var codeChallengeMethod = context.Request.Query["code_challenge_method"].ToString();
            var scope = context.Request.Query["scope"].ToString();

            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(redirectUri) || string.IsNullOrEmpty(state))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_request" });
                return;
            }

            try
            {
                var scopes = string.IsNullOrEmpty(scope)
                    ? null
                    : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();

                var authUrl = proxy.GetAuthorizationUrl(
                    clientId: clientId,
                    redirectUri: redirectUri,
                    state: state,
                    codeChallenge: string.IsNullOrEmpty(codeChallenge) ? null : codeChallenge,
                    codeChallengeMethod: string.IsNullOrEmpty(codeChallengeMethod) ? "S256" : codeChallengeMethod,
                    scopes: scopes);

                context.Response.Redirect(authUrl);
            }
            catch (Exception ex)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_request", error_description = ex.Message });
            }
        })
        .WithName("OAuthAuthorize")
        .AllowAnonymous();

        // Callback endpoint (handles upstream provider callback)
        app.MapGet("/auth/callback", async (HttpContext context) =>
        {
            var code = context.Request.Query["code"].ToString();
            var state = context.Request.Query["state"].ToString();
            var error = context.Request.Query["error"].ToString();

            if (!string.IsNullOrEmpty(error))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error, error_description = context.Request.Query["error_description"].ToString() });
                return;
            }

            if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(state))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_request" });
                return;
            }

            try
            {
                var tokenResponse = await proxy.HandleCallbackAsync(code, state);
                context.Response.Redirect(tokenResponse.RedirectUri);
            }
            catch (Exception ex)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_request", error_description = ex.Message });
            }
        })
        .WithName("OAuthCallback")
        .AllowAnonymous();

        // Token endpoint
        app.MapPost("/oauth/token", async (HttpContext context) =>
        {
            var form = await context.Request.ReadFormAsync();
            var grantType = form["grant_type"].ToString();

            try
            {
                if (grantType == "authorization_code")
                {
                    var code = form["code"].ToString();
                    var redirectUri = form["redirect_uri"].ToString();
                    var codeVerifier = form["code_verifier"].ToString();

                    if (string.IsNullOrEmpty(code) || string.IsNullOrEmpty(redirectUri))
                    {
                        context.Response.StatusCode = 400;
                        await context.Response.WriteAsJsonAsync(new { error = "invalid_request" });
                        return;
                    }

                    var tokenResponse = await proxy.ExchangeCodeForTokenAsync(
                        code: code,
                        redirectUri: redirectUri,
                        codeVerifier: string.IsNullOrEmpty(codeVerifier) ? null : codeVerifier);

                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsJsonAsync(new
                    {
                        access_token = tokenResponse.AccessToken,
                        token_type = tokenResponse.TokenType,
                        expires_in = tokenResponse.ExpiresIn,
                        refresh_token = tokenResponse.RefreshToken,
                        scope = tokenResponse.Scope
                    });
                }
                else if (grantType == "refresh_token")
                {
                    var refreshToken = form["refresh_token"].ToString();

                    if (string.IsNullOrEmpty(refreshToken))
                    {
                        context.Response.StatusCode = 400;
                        await context.Response.WriteAsJsonAsync(new { error = "invalid_request" });
                        return;
                    }

                    var tokenResponse = await proxy.RefreshTokenAsync(refreshToken);

                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsJsonAsync(new
                    {
                        access_token = tokenResponse.AccessToken,
                        token_type = tokenResponse.TokenType,
                        expires_in = tokenResponse.ExpiresIn,
                        refresh_token = tokenResponse.RefreshToken,
                        scope = tokenResponse.Scope
                    });
                }
                else
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsJsonAsync(new { error = "unsupported_grant_type" });
                }
            }
            catch (Exception ex)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_request", error_description = ex.Message });
            }
        })
        .WithName("OAuthToken")
        .AllowAnonymous();

        // Add to OAuthProxyEndpoints.cs:

        // OpenID Connect Userinfo endpoint
        app.MapGet("/oauth/userinfo", async (HttpContext context, ITokenVerifier tokenVerifier) =>
        {
            // Extract and validate bearer token
            var authHeader = context.Request.Headers["Authorization"].ToString();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new { error = "invalid_token" });
                return;
            }

            var token = authHeader.Substring("Bearer ".Length).Trim();
            var accessToken = await tokenVerifier.VerifyTokenAsync(token);

            if (accessToken == null)
            {
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsJsonAsync(new { error = "invalid_token" });
                return;
            }

            // Return user info claims
            var userInfo = new Dictionary<string, object>
            {
                ["sub"] = accessToken.ClientId,
            };

            // Add claims from the access token
            foreach (var claim in accessToken.Claims)
            {
                userInfo[claim.Key] = claim.Value;
            }

            context.Response.ContentType = "application/json";
            await context.Response.WriteAsJsonAsync(userInfo);
        })
        .WithName("OpenIdUserinfo")
        .RequireAuthorization();

        // Add to OAuthProxyEndpoints.cs:

        // Token Revocation endpoint (RFC 7009)
        app.MapPost("/oauth/revoke", async (HttpContext context, OAuthProxy proxy) =>
        {
            var form = await context.Request.ReadFormAsync();
            var token = form["token"].ToString();
            var tokenTypeHint = form["token_type_hint"].ToString();

            if (string.IsNullOrEmpty(token))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "invalid_request" });
                return;
            }

            try
            {
                // Revoke the token
                await proxy.RevokeTokenAsync(token, tokenTypeHint);
                
                context.Response.StatusCode = 200;
            }
            catch (Exception ex)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsJsonAsync(new { error = "server_error", error_description = ex.Message });
            }
        })
        .WithName("OAuthRevoke")
        .AllowAnonymous();
    }

    private class OAuthClientRegistrationRequest
    {
        public string? ClientId { get; set; }
        public string? ClientSecret { get; set; }
        public IReadOnlyList<string>? RedirectUris { get; set; }
        public IReadOnlyList<string>? GrantTypes { get; set; }
        public string? Scope { get; set; }
        public string? TokenEndpointAuthMethod { get; set; }
        public string? ClientName { get; set; }
    }
}