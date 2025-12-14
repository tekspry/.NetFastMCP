using FastMCP.Authentication.Configuration;
using FastMCP.Authentication.Extensions;
using FastMCP.Authentication.Providers.Auth0;
using FastMCP.Authentication.Providers.AWS;
using FastMCP.Authentication.Providers.AzureAd;
using FastMCP.Authentication.Providers.Descope;
using FastMCP.Authentication.Providers.Google;
using FastMCP.Authentication.Providers.GitHub;
using FastMCP.Authentication.Providers.Okta;
using FastMCP.Authentication.Providers.Supabase;
using FastMCP.Authentication.Providers.WorkOS;
using FastMCP.Authentication.Providers.Custom;
using FastMCP.Hosting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using AspNet.Security.OAuth.GitHub;
using Microsoft.Identity.Web;
using FastMCP.Authentication.Proxy;  // For OAuthProxy, OAuthProxyOptions, IClientStore
using FastMCP.Authentication.Core;    // For ITokenVerifier

namespace FastMCP.Hosting;

/// <summary>
/// Provides extension methods for configuring common authentication providers with FastMCP.
/// </summary>
public static class McpAuthenticationExtensions
{
    /// <summary>
    /// Configures Google OAuth 2.0 authentication.
    /// Requires "Authentication:Google:ClientId" and "Authentication:Google:ClientSecret" in configuration.
    /// </summary>
    /// <param name="builder">The <see cref="McpServerBuilder"/> instance.</param>
    /// <param name="configureOptions">Optional action to configure <see cref="GoogleOptions"/>.</param>
    public static McpServerBuilder AddGoogle(this McpServerBuilder builder, Action<GoogleOptions>? configureOptions = null)
    {
        builder.WithAuthentication(authBuilder =>
        {
            authBuilder.AddGoogle(GoogleDefaults.AuthenticationScheme, options =>
            {
                builder.GetWebAppBuilder().Configuration.GetSection("Authentication:Google").Bind(options);
                options.SignInScheme = McpAuthenticationConstants.ApplicationScheme; // Ensure sign-in uses our app cookie
                configureOptions?.Invoke(options);
            });
        });
        return builder;
    }

    /// <summary>
    /// Configures GitHub OAuth authentication.
    /// Requires "Authentication:GitHub:ClientId" and "Authentication:GitHub:ClientSecret" in configuration.
    /// </summary>
    /// <param name="builder">The <see cref="McpServerBuilder"/> instance.</param>
    /// <param name="configureOptions">Optional action to configure <see cref="GitHubOptions"/>.</param>
   public static McpServerBuilder AddGitHub(this McpServerBuilder builder, Action<GitHubAuthenticationOptions>? configureOptions = null) 
    {
        builder.WithAuthentication(authBuilder =>
        {
            authBuilder.AddGitHub(GitHubAuthenticationDefaults.AuthenticationScheme, options =>
            {
                // CHANGE THIS LINE: Remove the generic type argument for IConfigurationSection.Bind
                builder.GetWebAppBuilder().Configuration.GetSection("Authentication:GitHub").Bind(options);
                options.SignInScheme = McpAuthenticationConstants.ApplicationScheme;
                configureOptions?.Invoke(options);
            });
        });
        return builder;
    }

    /// <summary>
    /// Configures Azure Active Directory (OpenID Connect) authentication using Microsoft.Identity.Web.
    /// Requires "AzureAd" section in configuration with TenantId, ClientId, etc.
    /// </summary>
    /// <param name="builder">The <see cref="McpServerBuilder"/> instance.</param>
    public static McpServerBuilder AddAzureAd(this McpServerBuilder builder)
    {
        // AddMicrosoftIdentityWebAppAuthentication internally adds authentication and authorization services.
        // It also configures an OpenIdConnect scheme.
        builder.GetWebAppBuilder().Services.AddMicrosoftIdentityWebAppAuthentication(
            builder.GetWebAppBuilder().Configuration, "AzureAd");
        
        // Adjust the default challenge scheme if AzureAd is the primary auth method.
        // This might require more nuanced configuration depending on the exact flow.
        builder.WithAuthentication(authBuilder => {
            // No need to explicitly AddOpenIdConnect here as AddMicrosoftIdentityWebAppAuthentication already does.
            // Just ensure default challenge works as expected, or developers configure it explicitly.
        });
        return builder;
    }

    /// <summary>
    /// Configures generic OpenID Connect authentication (e.g., for Auth0, Okta, custom OIDC providers).
    /// Requires "Authentication:Oidc:Authority", "Authentication:Oidc:ClientId", "Authentication:Oidc:ClientSecret" in configuration.
    /// </summary>
    /// <param name="builder">The <see cref="McpServerBuilder"/> instance.</param>
    /// <param name="configureOptions">Action to configure <see cref="OpenIdConnectOptions"/>.</param>
    public static McpServerBuilder AddOidc(this McpServerBuilder builder, Action<OpenIdConnectOptions> configureOptions)
    {
        builder.WithAuthentication(authBuilder =>
        {
            authBuilder.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
            {
                builder.GetWebAppBuilder().Configuration.GetSection("Authentication:Oidc").Bind(options);
                options.SignInScheme = McpAuthenticationConstants.ApplicationScheme; // Ensure sign-in uses our app cookie
                configureOptions.Invoke(options);
            });
        });
        return builder;
    }

    /// <summary>
    /// Configures Google OAuth 2.0 authentication using token verifier.
    /// </summary>
    public static McpServerBuilder AddGoogleTokenVerifier(
        this McpServerBuilder builder,
        GoogleAuthOptions? options = null)
    {      
        
        options = LoadAuthOptions(builder, "Google", "Authentication:Google", options);

        if (string.IsNullOrEmpty(options.ClientId))
            throw new InvalidOperationException("Google ClientId is required");

        var tokenVerifier = new GoogleTokenVerifier(
            clientId: options.ClientId,
            requiredScopes: options.RequiredScopes,
            timeoutSeconds: options.TimeoutSeconds,
            logger: builder.GetWebAppBuilder().Services.BuildServiceProvider().GetService<ILogger<GoogleTokenVerifier>>());

        builder.WithAuthentication(authBuilder =>
        {
            authBuilder.AddTokenVerifier("Google", tokenVerifier);
        });

        // Set as default challenge scheme
        SetDefaultChallengeScheme(builder, "Google");

        return builder;
    }

    /// <summary>
    /// Configures GitHub OAuth authentication using token verifier.
    /// </summary>
    public static McpServerBuilder AddGitHubTokenVerifier(
        this McpServerBuilder builder,
        GitHubAuthOptions? options = null)
    {
        options = LoadAuthOptions(builder, "GitHub", "Authentication:GitHub", options);

        var tokenVerifier = new GitHubTokenVerifier(
            requiredScopes: options.RequiredScopes,
            timeoutSeconds: options.TimeoutSeconds,
            logger: builder.GetWebAppBuilder().Services.BuildServiceProvider().GetService<ILogger<GitHubTokenVerifier>>());

        builder.WithAuthentication(authBuilder =>
        {
            authBuilder.AddTokenVerifier("GitHub", tokenVerifier);
        });

        // Set as default challenge scheme
        SetDefaultChallengeScheme(builder, "GitHub");

        return builder;
    }

        /// <summary>
    /// Configures Azure AD authentication using token verifier.
    /// </summary>
    public static McpServerBuilder AddAzureAdTokenVerifier(
        this McpServerBuilder builder,
        AzureAdAuthOptions? options = null)
    {
        options = LoadAuthOptions(builder, "AzureAd", "Authentication:AzureAd", options);

        if (string.IsNullOrEmpty(options.TenantId))
            throw new InvalidOperationException("Azure AD TenantId is required");
        if (string.IsNullOrEmpty(options.ClientId))
            throw new InvalidOperationException("Azure AD ClientId is required");

        var tokenVerifier = new AzureAdTokenVerifier(
            tenantId: options.TenantId,
            clientId: options.ClientId,
            requiredScopes: options.RequiredScopes,
            baseAuthority: options.BaseAuthority,
            logger: builder.GetWebAppBuilder().Services.BuildServiceProvider().GetService<ILogger<AzureAdTokenVerifier>>());

        builder.WithAuthentication(authBuilder =>
        {
            authBuilder.AddTokenVerifier("AzureAd", tokenVerifier);
        });

        // Set as default challenge scheme
        SetDefaultChallengeScheme(builder, "AzureAd");

        return builder;
    }

    /// <summary>
    /// Configures Okta authentication using token verifier.
    /// </summary>
    public static McpServerBuilder AddOkta(
        this McpServerBuilder builder,
        OktaAuthOptions? options = null)
    {
        options = LoadAuthOptions(builder, "Okta", "Authentication:Okta", options);

        if (string.IsNullOrEmpty(options.Domain))
            throw new InvalidOperationException("Okta Domain is required");

        ITokenVerifier tokenVerifier;
        if (options.UseIntrospection && !string.IsNullOrEmpty(options.ClientSecret))
        {
            tokenVerifier = new OktaTokenVerifier(
                oktaDomain: options.Domain,
                clientId: options.ClientId ?? string.Empty,
                clientSecret: options.ClientSecret,
                audience: options.Audience,
                requiredScopes: options.RequiredScopes,
                timeoutSeconds: options.TimeoutSeconds,
                logger: builder.GetWebAppBuilder().Services.BuildServiceProvider().GetService<ILogger<OktaTokenVerifier>>(),
                useIntrospection: true);
        }
        else
        {
            tokenVerifier = new OktaTokenVerifier(
                oktaDomain: options.Domain,
                audience: options.Audience,
                requiredScopes: options.RequiredScopes,
                logger: builder.GetWebAppBuilder().Services.BuildServiceProvider().GetService<ILogger<OktaTokenVerifier>>());
        }

        builder.WithAuthentication(authBuilder =>
        {
            authBuilder.AddTokenVerifier("Okta", tokenVerifier);
        });

        // Set as default challenge scheme
        SetDefaultChallengeScheme(builder, "Okta");

        return builder;
    }

    /// <summary>
    /// Configures Auth0 authentication using token verifier.
    /// </summary>
    public static McpServerBuilder AddAuth0(
        this McpServerBuilder builder,
        Auth0AuthOptions? options = null)
    {
        options = LoadAuthOptions(builder, "Auth0", "Authentication:Auth0", options);

        if (string.IsNullOrEmpty(options.ConfigUrl))
            throw new InvalidOperationException("Auth0 ConfigUrl is required");

        var tokenVerifier = new Auth0TokenVerifier(
            configUrl: options.ConfigUrl,
            audience: options.Audience,
            requiredScopes: options.RequiredScopes,
            logger: builder.GetWebAppBuilder().Services.BuildServiceProvider().GetService<ILogger<Auth0TokenVerifier>>());

        builder.WithAuthentication(authBuilder =>
        {
            authBuilder.AddTokenVerifier("Auth0", tokenVerifier);
        });

        // Set as default challenge scheme
        SetDefaultChallengeScheme(builder, "Auth0");

        return builder;
    }

    /// <summary>
    /// Configures AWS Cognito authentication using token verifier.
    /// </summary>
    public static McpServerBuilder AddAwsCognito(
        this McpServerBuilder builder,
        AwsCognitoAuthOptions? options = null)
    {
        options = LoadAuthOptions(builder, "AwsCognito", "Authentication:AwsCognito", options);

        if (string.IsNullOrEmpty(options.UserPoolId))
            throw new InvalidOperationException("AWS Cognito UserPoolId is required");

        var tokenVerifier = new AwsCognitoTokenVerifier(
            userPoolId: options.UserPoolId,
            awsRegion: options.AwsRegion,
            audience: options.Audience,
            requiredScopes: options.RequiredScopes,
            logger: builder.GetWebAppBuilder().Services.BuildServiceProvider().GetService<ILogger<AwsCognitoTokenVerifier>>());

        builder.WithAuthentication(authBuilder =>
        {
            authBuilder.AddTokenVerifier("AwsCognito", tokenVerifier);
        });

        // Set as default challenge scheme
        SetDefaultChallengeScheme(builder, "AwsCognito");

        return builder;
    }

        /// <summary>
    /// Configures custom authentication using a custom provider.
    /// </summary>
    public static McpServerBuilder AddCustomAuth<TProvider>(
        this McpServerBuilder builder,
        string schemeName,
        TProvider provider)
        where TProvider : CustomAuthProvider
    {
        if (string.IsNullOrEmpty(schemeName))
            throw new ArgumentException("Scheme name cannot be null or empty", nameof(schemeName));
        if (provider == null)
            throw new ArgumentNullException(nameof(provider));

        builder.WithAuthentication(authBuilder =>
        {
            authBuilder.AddTokenVerifier(schemeName, provider);
        });

        // Set as default challenge scheme
        SetDefaultChallengeScheme(builder, schemeName);

        return builder;
    }

    // Add this private helper method to McpAuthenticationExtensions class
    private static void SetDefaultChallengeScheme(McpServerBuilder builder, string schemeName)
    {
        // Set as default challenge scheme for bearer token authentication
        builder.WithDefaultChallengeScheme(schemeName);
        
        // Also update the authentication options
        builder.GetWebAppBuilder().Services.Configure<AuthenticationOptions>(options =>
        {
            options.DefaultChallengeScheme = schemeName;
        });
    }

    /// <summary>
    /// Configures OAuth Proxy for Google (non-DCR provider).
    /// </summary>
    public static McpServerBuilder AddGoogleOAuthProxy(
        this McpServerBuilder builder,
        GoogleAuthOptions? options = null)
    {
        options = LoadAuthOptions(builder, "Google", "Authentication:Google", options);

        if (string.IsNullOrEmpty(options.ClientId))
            throw new InvalidOperationException("Google ClientId is required");
        if (string.IsNullOrEmpty(options.ClientSecret))
            throw new InvalidOperationException("Google ClientSecret is required");

        var tokenVerifier = new GoogleTokenVerifier(
            clientId: options.ClientId,
            requiredScopes: options.RequiredScopes,
            timeoutSeconds: options.TimeoutSeconds,
            logger: builder.GetWebAppBuilder().Services.BuildServiceProvider().GetService<ILogger<GoogleTokenVerifier>>());

        var proxyOptions = new OAuthProxyOptions
        {
            UpstreamAuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth",
            UpstreamTokenEndpoint = "https://oauth2.googleapis.com/token",
            UpstreamClientId = options.ClientId,
            UpstreamClientSecret = options.ClientSecret!,
            BaseUrl = builder.GetWebAppBuilder().Configuration["BaseUrl"] ?? "http://localhost:5000",
            RedirectPath = "/auth/callback",
            ValidScopes = options.RequiredScopes,
            ForwardPkce = true
        };

        builder.WithOAuthProxy(proxyOptions, tokenVerifier);
        SetDefaultChallengeScheme(builder, "OAuthProxy");

        return builder;
    }

    /// <summary>
    /// Configures OAuth Proxy for GitHub (non-DCR provider).
    /// </summary>
    public static McpServerBuilder AddGitHubOAuthProxy(
        this McpServerBuilder builder,
        GitHubAuthOptions? options = null)
    {
        options = LoadAuthOptions(builder, "GitHub", "Authentication:GitHub", options);

        if (string.IsNullOrEmpty(options.ClientId))
            throw new InvalidOperationException("GitHub ClientId is required");
        if (string.IsNullOrEmpty(options.ClientSecret))
            throw new InvalidOperationException("GitHub ClientSecret is required");

        var tokenVerifier = new GitHubTokenVerifier(
            requiredScopes: options.RequiredScopes,
            timeoutSeconds: options.TimeoutSeconds,
            logger: builder.GetWebAppBuilder().Services.BuildServiceProvider().GetService<ILogger<GitHubTokenVerifier>>());

        var proxyOptions = new OAuthProxyOptions
        {
            UpstreamAuthorizationEndpoint = "https://github.com/login/oauth/authorize",
            UpstreamTokenEndpoint = "https://github.com/login/oauth/access_token",
            UpstreamClientId = options.ClientId,
            UpstreamClientSecret = options.ClientSecret!,
            BaseUrl = builder.GetWebAppBuilder().Configuration["BaseUrl"] ?? "http://localhost:5000",
            RedirectPath = "/auth/callback",
            ValidScopes = options.RequiredScopes,
            ForwardPkce = true
        };

        builder.WithOAuthProxy(proxyOptions, tokenVerifier);
        SetDefaultChallengeScheme(builder, "OAuthProxy");
        return builder;
    }

    /// <summary>
    /// Configures OAuth Proxy for Azure AD (non-DCR provider).
    /// </summary>
    public static McpServerBuilder AddAzureAdOAuthProxy(
        this McpServerBuilder builder,
        AzureAdAuthOptions? options = null)
    {
        options = LoadAuthOptions(builder, "AzureAd", "Authentication:AzureAd", options);

        if (string.IsNullOrEmpty(options.TenantId))
            throw new InvalidOperationException("Azure AD TenantId is required");
        if (string.IsNullOrEmpty(options.ClientId))
            throw new InvalidOperationException("Azure AD ClientId is required");
        if (string.IsNullOrEmpty(options.ClientSecret))
            throw new InvalidOperationException("Azure AD ClientSecret is required");

        var tokenVerifier = new AzureAdTokenVerifier(
            tenantId: options.TenantId,
            clientId: options.ClientId,
            requiredScopes: options.RequiredScopes,
            baseAuthority: options.BaseAuthority,
            logger: builder.GetWebAppBuilder().Services.BuildServiceProvider().GetService<ILogger<AzureAdTokenVerifier>>());

        var baseAuthority = options.BaseAuthority;
        var proxyOptions = new OAuthProxyOptions
        {
            UpstreamAuthorizationEndpoint = $"https://{baseAuthority}/{options.TenantId}/oauth2/v2.0/authorize",
            UpstreamTokenEndpoint = $"https://{baseAuthority}/{options.TenantId}/oauth2/v2.0/token",
            UpstreamClientId = options.ClientId,
            UpstreamClientSecret = options.ClientSecret!,
            BaseUrl = builder.GetWebAppBuilder().Configuration["BaseUrl"] ?? "http://localhost:5000",
            RedirectPath = "/auth/callback",
            ValidScopes = options.RequiredScopes,
            ForwardPkce = true
        };

        builder.WithOAuthProxy(proxyOptions, tokenVerifier);
        SetDefaultChallengeScheme(builder, "OAuthProxy");
        return builder;
    }

    /// <summary>
    /// Configures OAuth Proxy for AWS Cognito (non-DCR provider).
    /// </summary>
    public static McpServerBuilder AddAwsCognitoOAuthProxy(
        this McpServerBuilder builder,
        AwsCognitoAuthOptions? options = null)
    {
            
        options = LoadAuthOptions(builder, "AwsCognito", "Authentication:AwsCognito", options);

        if (string.IsNullOrEmpty(options.UserPoolId))
            throw new InvalidOperationException("AWS Cognito UserPoolId is required");
        if (string.IsNullOrEmpty(options.ClientId))
            throw new InvalidOperationException("AwsCognito ClientId is required");
        if (string.IsNullOrEmpty(options.ClientSecret))
            throw new InvalidOperationException("AwsCognito ClientSecret is required");

        var tokenVerifier = new AwsCognitoTokenVerifier(
            userPoolId: options.UserPoolId,
            awsRegion: options.AwsRegion,
            audience: options.Audience,
            requiredScopes: options.RequiredScopes,
            logger: builder.GetWebAppBuilder().Services.BuildServiceProvider().GetService<ILogger<AwsCognitoTokenVerifier>>());


        var proxyOptions = new OAuthProxyOptions
        {
            UpstreamAuthorizationEndpoint = $"https://cognito-idp.{options.AwsRegion}.amazonaws.com/{options.UserPoolId}/oauth2/authorize",
            UpstreamTokenEndpoint = $"https://cognito-idp.{options.AwsRegion}.amazonaws.com/{options.UserPoolId}/oauth2/token",
            UpstreamClientId = options.ClientId,
            UpstreamClientSecret = options.ClientSecret!,
            BaseUrl = builder.GetWebAppBuilder().Configuration["BaseUrl"] ?? "http://localhost:5000",
            RedirectPath = "/auth/callback",
            ValidScopes = options.RequiredScopes,
            ForwardPkce = true
        };

        builder.WithOAuthProxy(proxyOptions, tokenVerifier);
        SetDefaultChallengeScheme(builder, "OAuthProxy");

        return builder;
    }

    /// <summary>
    /// Configures OAuth Proxy for Auth0 (non-DCR provider).
    /// </summary>
    public static McpServerBuilder AddAuth0OAuthProxy(
        this McpServerBuilder builder,
        Auth0AuthOptions? options = null)
    {
        options = LoadAuthOptions(builder, "Auth0", "Authentication:Auth0", options);

        if (string.IsNullOrEmpty(options.ConfigUrl))
            throw new InvalidOperationException("Auth0 ConfigUrl is required");
        if (string.IsNullOrEmpty(options.ClientId))
            throw new InvalidOperationException("Auth0 ClientId is required");
        if (string.IsNullOrEmpty(options.ClientSecret))
            throw new InvalidOperationException("Auth0 ClientSecret is required");

        var tokenVerifier = new Auth0TokenVerifier(
            configUrl: options.ConfigUrl,
            audience: options.Audience,
            requiredScopes: options.RequiredScopes,
            logger: builder.GetWebAppBuilder().Services.BuildServiceProvider().GetService<ILogger<Auth0TokenVerifier>>());


        var configUrl = options.ConfigUrl;
        if (!configUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && 
            !configUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            configUrl = $"https://{configUrl}";
        }  

        var proxyOptions = new OAuthProxyOptions
        {
            UpstreamAuthorizationEndpoint = $"{configUrl}/oauth/authorize",
            UpstreamTokenEndpoint = $"{configUrl}/oauth/token",
            UpstreamClientId = options.ClientId,
            UpstreamClientSecret = options.ClientSecret!,
            IssuerUrl = configUrl,
            BaseUrl = builder.GetWebAppBuilder().Configuration["BaseUrl"] ?? "http://localhost:5000",
            RedirectPath = "/auth/callback",
            ValidScopes = options.RequiredScopes,
            ForwardPkce = true
        };

        builder.WithOAuthProxy(proxyOptions, tokenVerifier);
        SetDefaultChallengeScheme(builder, "OAuthProxy");

        return builder;
    }

     /// <summary>
    /// Configures OAuth Proxy for Okta (non-DCR provider).
    /// </summary>
    public static McpServerBuilder AddOktaOAuthProxy(
        this McpServerBuilder builder,
        OktaAuthOptions? options = null)
    {
        options = LoadAuthOptions(builder, "Okta", "Authentication:Okta", options);

        if (string.IsNullOrEmpty(options.Domain))
            throw new InvalidOperationException("Okta Domain is required");
        if (string.IsNullOrEmpty(options.ClientId))
            throw new InvalidOperationException("Okta ClientId is required");
        if (string.IsNullOrEmpty(options.ClientSecret))
            throw new InvalidOperationException("Okta ClientSecret is required");

        var tokenVerifier = new OktaTokenVerifier(
            oktaDomain: options.Domain,
            clientId: options.ClientId,
            clientSecret: options.ClientSecret,
            audience: options.Audience,
            requiredScopes: options.RequiredScopes,
            logger: builder.GetWebAppBuilder().Services.BuildServiceProvider().GetService<ILogger<OktaTokenVerifier>>());

        var domain = options.Domain;
        if (!domain.StartsWith("http://") && !domain.StartsWith("https://"))
        {
            domain = $"https://{domain}";
        }

        var proxyOptions = new OAuthProxyOptions
        {
            UpstreamAuthorizationEndpoint = $"{domain}/oauth/authorize",
            UpstreamTokenEndpoint = $"{domain}/oauth/token",
            UpstreamClientId = options.ClientId,
            UpstreamClientSecret = options.ClientSecret!,
            IssuerUrl = domain,
            BaseUrl = builder.GetWebAppBuilder().Configuration["BaseUrl"] ?? "http://localhost:5000",
            RedirectPath = "/auth/callback",
            ValidScopes = options.RequiredScopes,
            ForwardPkce = true
        };

        builder.WithOAuthProxy(proxyOptions, tokenVerifier);
        SetDefaultChallengeScheme(builder, "OAuthProxy");

        return builder;
    }

    /// <summary>
    /// Loads authentication options from configuration or environment variables.
    /// </summary>
    private static TOptions LoadAuthOptions<TOptions>(
        McpServerBuilder builder,
        string providerName,
        string configSection,
        TOptions? providedOptions = null)
        where TOptions : class, new()
    {
        // Check if environment variable indicates this provider should be used
        var envAuthProvider = Environment.GetEnvironmentVariable("FASTMCP_SERVER_AUTH");
        var providerClassName = $"{providerName}TokenVerifier";
        var fullProviderPath = $"fastmcp.authentication.providers.{providerName.ToLowerInvariant()}.{providerClassName}";

        if (envAuthProvider == fullProviderPath || envAuthProvider == providerClassName)
        {
            // Load from environment variables
            var options = builder.GetWebAppBuilder().Configuration.GetAuthOptions<TOptions>(configSection);

            // Parse scopes from environment variable if present
            var scopeEnv = Environment.GetEnvironmentVariable($"FASTMCP_SERVER_AUTH_{providerName.ToUpperInvariant()}_REQUIRED_SCOPES");
            if (!string.IsNullOrEmpty(scopeEnv))
            {
                // Use reflection to set RequiredScopes if the property exists
                var scopeProperty = typeof(TOptions).GetProperty("RequiredScopes");
                if (scopeProperty != null && scopeProperty.CanWrite)
                {
                    var scopes = AuthConfigurationExtensions.ParseScopes(scopeEnv);
                    scopeProperty.SetValue(options, scopes);
                }
            }

            return options;
        }
        else
        {
            // Load from configuration
            providedOptions ??= new TOptions();
            builder.GetWebAppBuilder().Configuration.GetSection(configSection).Bind(providedOptions);
            return providedOptions;
        }
    }
}