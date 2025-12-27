using FastMCP.Authentication.Configuration;
using FastMCP.Authentication.Extensions;
using FastMCP.Authentication.Providers.Auth0;
using FastMCP.Authentication.Providers.AWS;
using FastMCP.Authentication.Providers.AzureAd;
using FastMCP.Authentication.Providers.Google;
using FastMCP.Authentication.Providers.GitHub;
using FastMCP.Authentication.Providers.Okta;
using FastMCP.Authentication.Providers.Custom;
using FastMCP.Hosting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System;
using System.Linq;
using AspNet.Security.OAuth.GitHub;
using Microsoft.Identity.Web;
using FastMCP.Authentication.Proxy;
using FastMCP.Authentication.Core;

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
        var config = builder.GetWebAppBuilder().Configuration;
        var logger = builder.GetWebAppBuilder().Services.BuildServiceProvider().GetService<ILogger>();

        var clientId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID", "Google:ClientId");
        var clientSecret = GetConfigValue(config, "FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET", "Google:ClientSecret");

        if (!string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(clientSecret))
        {
            logger?.LogInformation("Google OAuth authentication: Credentials detected, configuring provider...");

            try
            {
                var googleTokenVerifier = new GoogleTokenVerifier(
                    clientId: clientId,
                    requiredScopes: null,
                    timeoutSeconds: 10,
                    logger: logger as ILogger<GoogleTokenVerifier>);

                builder.WithAuthentication(auth =>
                {
                    auth.AddGoogle(options =>
                    {
                        options.ClientId = clientId;
                        options.ClientSecret = clientSecret;
                    });
                });

                logger?.LogInformation("Google OAuth authentication configured successfully");
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Failed to configure Google authentication");
                throw;
            }
        }
        else
        {
            logger?.LogWarning(
                "Google OAuth authentication: Credentials not found. " +
                "Set FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID and FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET " +
                "environment variables to enable authentication.");
        }

        return builder;
    }

    /// <summary>
    /// Configures GitHub OAuth authentication.
    /// Requires "Authentication:GitHub:ClientId" and "Authentication:GitHub:ClientSecret" in configuration.
    /// </summary>
    /// <param name="builder">The <see cref="McpServerBuilder"/> instance.</param>
    public static McpServerBuilder AddGitHub(this McpServerBuilder builder)
    {
        var config = builder.GetWebAppBuilder().Configuration;
        var logger = builder.GetWebAppBuilder().Services.BuildServiceProvider().GetService<ILogger>();

        var clientId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_GITHUB_CLIENT_ID", "GitHub:ClientId");
        var clientSecret = GetConfigValue(config, "FASTMCP_SERVER_AUTH_GITHUB_CLIENT_SECRET", "GitHub:ClientSecret");

        if (!string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(clientSecret))
        {
            logger?.LogInformation("GitHub OAuth authentication: Credentials detected, configuring provider...");

            try
            {
                var githubTokenVerifier = new GitHubTokenVerifier(
                    requiredScopes: null,
                    timeoutSeconds: 10,
                    logger: logger as ILogger<GitHubTokenVerifier>);

                builder.WithAuthentication(auth =>
                {
                    auth.AddGitHub(GitHubAuthenticationDefaults.AuthenticationScheme, options =>
                    {
                        options.ClientId = clientId;
                        options.ClientSecret = clientSecret;
                        options.SignInScheme = McpAuthenticationConstants.ApplicationScheme;
                    });
                });

                logger?.LogInformation("GitHub OAuth authentication configured successfully");
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Failed to configure GitHub authentication");
                throw;
            }
        }
        else
        {
            logger?.LogWarning(
                "GitHub OAuth authentication: Credentials not found. " +
                "Set FASTMCP_SERVER_AUTH_GITHUB_CLIENT_ID and FASTMCP_SERVER_AUTH_GITHUB_CLIENT_SECRET " +
                "environment variables to enable authentication.");
        }

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
        var config = builder.GetWebAppBuilder().Configuration;
        var logger = builder.GetWebAppBuilder().Services.BuildServiceProvider().GetService<ILogger>();
        
        // Try to load Azure AD configuration
        var clientId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AZUREAD_CLIENT_ID", "AzureAd:ClientId");
        var tenantId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AZUREAD_TENANT_ID", "AzureAd:TenantId");
        var clientSecret = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AZUREAD_CLIENT_SECRET", "AzureAd:ClientSecret");


        // Only register if all required credentials are present
        if (!string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(tenantId))
        {
            logger?.LogInformation("Azure AD authentication: Credentials detected, configuring provider...");

            try
            {
                var azureTokenVerifier = new AzureAdTokenVerifier(
                    tenantId: tenantId,
                    clientId: clientId,
                    requiredScopes: null,
                    baseAuthority: "login.microsoftonline.com",
                    logger: logger as ILogger<AzureAdTokenVerifier>);
                
                builder.WithAuthentication(auth =>
                {
                    // Configure JWT Bearer token authentication for API calls (Bearer tokens)
                    auth.AddJwtBearer("Bearer", options =>
                    {
                        options.Authority = $"https://login.microsoftonline.com/{tenantId}/v2.0";
                        options.Audience = clientId;
                        options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                        {
                            ValidateIssuer = true,
                            ValidateAudience = true,
                            ValidateLifetime = true,
                            ValidateIssuerSigningKey = true,
                            ValidIssuer = $"https://login.microsoftonline.com/{tenantId}/v2.0"
                        };
                    });
                    
                    // Configure OpenIdConnect for interactive web login
                    auth.AddMicrosoftIdentityWebApp(options =>
                    {
                        options.Instance = "https://login.microsoftonline.com/";
                        options.TenantId = tenantId;
                        options.ClientId = clientId;
                        if (!string.IsNullOrEmpty(clientSecret))
                        {
                            options.ClientSecret = clientSecret;
                        }
                    });
                });

                logger?.LogInformation("Azure AD authentication configured successfully (JWT Bearer + OpenIdConnect)");
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Failed to configure Azure AD authentication");
                throw;
            }
        }
        else
        {
            logger?.LogWarning(
                "Azure AD authentication: Credentials not found. " +
                "Set FASTMCP_SERVER_AUTH_AZUREAD_CLIENT_ID and FASTMCP_SERVER_AUTH_AZUREAD_TENANT_ID " +
                "environment variables to enable authentication.");
        }

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
        var config = builder.GetWebAppBuilder().Configuration;
         var services = builder.GetWebAppBuilder().Services; // Get the IServiceCollection
        var logger = services.BuildServiceProvider().GetService<ILogger>(); // Use services here
        
        var clientId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID", "Google:ClientId");
        var clientSecret = GetConfigValue(config, "FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET", "Google:ClientSecret");
        var timeoutSeconds = 10;
        var requiredScopes = options?.RequiredScopes;

        if (!string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(clientSecret))
        {
            logger?.LogInformation("Google token verifier authentication: Credentials detected, configuring provider...");

            try
            {
                var tokenVerifier = new GoogleTokenVerifier(
                    clientId: clientId,
                    requiredScopes: requiredScopes,
                    timeoutSeconds: timeoutSeconds,
                    logger: logger as ILogger<GoogleTokenVerifier>);

                // Register the ITokenVerifier instance with the service collection
                services.AddSingleton<ITokenVerifier>(tokenVerifier); 
                
                builder.WithAuthentication(authBuilder =>
                {
                    authBuilder.AddTokenVerifier("Google", tokenVerifier);
                });


                SetDefaultChallengeScheme(builder, "Google");
                logger?.LogInformation("Google token verifier authentication configured successfully");

                // Configure default OAuth Proxy options for Google
                var defaultProxyOptions = new OAuthProxyOptions
                {
                    BaseUrl = "http://localhost:5002",
                    UpstreamClientId = clientId,
                    UpstreamClientSecret = clientSecret,
                    UpstreamAuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth",
                    UpstreamTokenEndpoint = "https://oauth2.googleapis.com/token",
                    UpstreamRevocationEndpoint = "https://oauth2.googleapis.com/revoke",
                    ValidScopes = requiredScopes?.ToList() ?? new List<string> 
                    { 
                        "openid", 
                        "profile", 
                        "email", 
                        "https://www.googleapis.com/auth/userinfo.profile" 
                    }
                };

                // Create a client store and register this client
                var clientStore = new InMemoryClientStore();
                var clientRegistration = new OAuthClientRegistration
                {
                    ClientId = clientId,
                    ClientSecret = clientSecret,
                    RedirectUris = new List<string> { "http://localhost:5002/auth/callback" },
                    AllowedRedirectUriPatterns = new List<string> { "http://localhost:*/auth/callback" }
                };
                clientStore.StoreClientAsync(clientId, clientRegistration).GetAwaiter().GetResult();

                // Register OAuth Proxy with the pre-configured client store
                builder.WithOAuthProxy(defaultProxyOptions, tokenVerifier, clientStore);

            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Failed to configure Google token verifier authentication");
                throw;
            }
        }
        else
        {
            logger?.LogWarning(
                "Google token verifier authentication: Credentials not found. " +
                "Set FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID and FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET " +
                "environment variables to enable authentication.");
        }

        return builder;
    }

    /// <summary>
    /// Configures GitHub OAuth authentication using token verifier.
    /// </summary>
    public static McpServerBuilder AddGitHubTokenVerifier(
        this McpServerBuilder builder,
        GitHubAuthOptions? options = null)
    {
        var config = builder.GetWebAppBuilder().Configuration;
        var services = builder.GetWebAppBuilder().Services; // Get the IServiceCollection
        var logger = services.BuildServiceProvider().GetService<ILogger>(); // Use services here
        
        var clientId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_GITHUB_CLIENT_ID", "GitHub:ClientId");
        var clientSecret = GetConfigValue(config, "FASTMCP_SERVER_AUTH_GITHUB_CLIENT_SECRET", "GitHub:ClientSecret");
        var timeoutSeconds = 10;
        var requiredScopes = options?.RequiredScopes;

        if (!string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(clientSecret))
        {
            logger?.LogInformation("GitHub token verifier authentication: Credentials detected, configuring provider...");

            try
            {
                var tokenVerifier = new GitHubTokenVerifier(
                    requiredScopes: requiredScopes,
                    timeoutSeconds: timeoutSeconds,
                    logger: logger as ILogger<GitHubTokenVerifier>);

                // Register the ITokenVerifier instance with the service collection
                services.AddSingleton<ITokenVerifier>(tokenVerifier); 
                
                builder.WithAuthentication(authBuilder =>
                {
                    authBuilder.AddTokenVerifier("GitHub", tokenVerifier);
                });


                SetDefaultChallengeScheme(builder, "GitHub");
                logger?.LogInformation("GitHub token verifier authentication configured successfully");

                // Configure default OAuth Proxy options for GitHub
                var defaultProxyOptions = new OAuthProxyOptions
                {
                    BaseUrl = "http://localhost:5002",
                    UpstreamClientId = clientId,
                    UpstreamClientSecret = clientSecret,
                    UpstreamAuthorizationEndpoint = "https://github.com/login/oauth/authorize",
                    UpstreamTokenEndpoint = "https://github.com/login/oauth/access_token",
                    // GitHub doesn't have a standard revocation endpoint
                    ValidScopes = requiredScopes?.ToList() ?? new List<string> 
                    { 
                        "read:user", 
                        "user:email" 
                    }
                };

                // Create a client store and register this client
                var clientStore = new InMemoryClientStore();
                var clientRegistration = new OAuthClientRegistration
                {
                    ClientId = clientId,
                    ClientSecret = clientSecret,
                    RedirectUris = new List<string> { "http://localhost:5002/auth/callback" },
                    AllowedRedirectUriPatterns = new List<string> { "http://localhost:*/auth/callback" }
                };
                clientStore.StoreClientAsync(clientId, clientRegistration).GetAwaiter().GetResult();

                // Register OAuth Proxy with the pre-configured client store
                builder.WithOAuthProxy(defaultProxyOptions, tokenVerifier, clientStore);

            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Failed to configure GitHub token verifier authentication");
                throw;
            }
        }
        else
        {
            logger?.LogWarning(
                "GitHub token verifier authentication: Credentials not found. " +
                "Set FASTMCP_SERVER_AUTH_GITHUB_CLIENT_ID and FASTMCP_SERVER_AUTH_GITHUB_CLIENT_SECRET " +
                "environment variables to enable authentication.");
        }

        return builder;
    }

        /// <summary>
    /// Configures Azure AD authentication using token verifier.
    /// </summary>
    public static McpServerBuilder AddAzureAdTokenVerifier(
        this McpServerBuilder builder,
        AzureAdAuthOptions? options = null)
    {
        var config = builder.GetWebAppBuilder().Configuration;
        var services = builder.GetWebAppBuilder().Services; 
        
        // Build a temporary ServiceProvider to get the logger factory
        // This is necessary because we are instantiating the verifier manually here
        var sp = services.BuildServiceProvider();
        var loggerFactory = sp.GetService<ILoggerFactory>();
        var logger = loggerFactory?.CreateLogger<AzureAdTokenVerifier>();
        
        var tenantId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AZUREAD_TENANT_ID", "AzureAd:TenantId");
        var clientId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AZUREAD_CLIENT_ID", "AzureAd:ClientId");
        var clientSecret = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AZUREAD_CLIENT_SECRET", "AzureAd:ClientSecret");
        var baseAuthority = options?.BaseAuthority ?? "login.microsoftonline.com";
        var requiredScopes = options?.RequiredScopes;

        if (!string.IsNullOrEmpty(tenantId) && !string.IsNullOrEmpty(clientId))
        {
            logger?.LogInformation("Azure AD token verifier authentication: Credentials detected, configuring provider...");

            try
            {
                var tokenVerifier = new AzureAdTokenVerifier(
                    tenantId: tenantId,
                    clientId: clientId,
                    requiredScopes: requiredScopes,
                    baseAuthority: baseAuthority,
                    logger: logger);

                // Register the ITokenVerifier instance with the service collection
                services.AddSingleton<ITokenVerifier>(tokenVerifier); 
                
                builder.WithAuthentication(authBuilder =>
                {
                    authBuilder.AddTokenVerifier("AzureAd", tokenVerifier);
                });

                SetDefaultChallengeScheme(builder, "AzureAd");
                logger?.LogInformation("Azure AD token verifier authentication configured successfully");

                // Configure default OAuth Proxy options for Azure AD
                var defaultProxyOptions = new OAuthProxyOptions
                {
                    BaseUrl = "http://localhost:5002", // Required for constructing absolute redirect URIs
                    UpstreamClientId = clientId,
                    UpstreamClientSecret = clientSecret ?? string.Empty,
                    UpstreamAuthorizationEndpoint = $"https://{baseAuthority}/{tenantId}/oauth2/v2.0/authorize",
                    UpstreamTokenEndpoint = $"https://{baseAuthority}/{tenantId}/oauth2/v2.0/token",
                    // Revocation is not standard in v2, leaving null
                    ValidScopes = requiredScopes?.ToList() ?? new List<string> { "openid", "profile", "email", "offline_access" }
                };

                // Create a client store and register this client so the proxy accepts it
                var clientStore = new InMemoryClientStore();
                // We use the same ClientID for the proxy client as the upstream ClientID for simplicity in this helper
                var clientRegistration = new OAuthClientRegistration
                {
                    ClientId = clientId,
                    ClientSecret = clientSecret ?? string.Empty,
                    RedirectUris = new List<string> { "http://localhost:5002/client-callback" }, // Separate client callback from proxy callback
                    AllowedRedirectUriPatterns = new List<string> { "http://localhost:*/client-callback" } // Allow any port on localhost
                };
                // We need to wait for the task, but we are in a sync method context (usually). 
                // However, StoreClientAsync is async. For extensions, we might need to block or use a different pattern.
                // InMemoryClientStore.StoreClientAsync is actually just a dictionary add, so it returns completed task.
                clientStore.StoreClientAsync(clientId, clientRegistration).GetAwaiter().GetResult();

                // Register OAuth Proxy with the pre-configured client store
                builder.WithOAuthProxy(defaultProxyOptions, tokenVerifier, clientStore);
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Failed to configure Azure AD token verifier authentication");
                throw;
            }
        }
        else
        {
            logger?.LogWarning(
                "Azure AD token verifier authentication: Credentials not found. " +
                "Set FASTMCP_SERVER_AUTH_AZUREAD_TENANT_ID and FASTMCP_SERVER_AUTH_AZUREAD_CLIENT_ID " +
                "environment variables to enable authentication.");
        }

        return builder;
    }

    public static McpServerBuilder AddAwsCognitoTokenVerifier(
        this McpServerBuilder builder,
        AwsCognitoAuthOptions? options = null)
    {
        var config = builder.GetWebAppBuilder().Configuration;
        var services = builder.GetWebAppBuilder().Services; // Get the IServiceCollection
        var logger = services.BuildServiceProvider().GetService<ILogger>(); // Use services here

        var userPoolId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AWSCOGNITO_USER_POOL_ID", "AwsCognito:UserPoolId");
        var region = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AWSCOGNITO_REGION", "AwsCognito:Region");
        var clientId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AWSCOGNITO_CLIENT_ID", "AwsCognito:ClientId");
        var clientSecret = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AWSCOGNITO_CLIENT_SECRET", "AwsCognito:ClientSecret");
        var cognitoDomain = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AWSCOGNITO_DOMAIN", "AwsCognito:Domain");
        var requiredScopes = options?.RequiredScopes;

        if (!string.IsNullOrEmpty(userPoolId) && !string.IsNullOrEmpty(region))
        {
            logger?.LogInformation("AWS Cognito token verifier authentication: Credentials detected, configuring provider...");

            try
            {
                var tokenVerifier = new AwsCognitoTokenVerifier(
                    userPoolId: userPoolId,
                    awsRegion: region ?? "us-east-1",
                    audience: null,
                    requiredScopes: requiredScopes,
                    logger: logger as ILogger<AwsCognitoTokenVerifier>);

                // Register the ITokenVerifier instance with the service collection
                services.AddSingleton<ITokenVerifier>(tokenVerifier); 

                builder.WithAuthentication(authBuilder =>
                {
                    authBuilder.AddTokenVerifier("AwsCognito", tokenVerifier);
                });

                SetDefaultChallengeScheme(builder, "AwsCognito");
                logger?.LogInformation("AWS Cognito token verifier authentication configured successfully");

                // Configure OAuth Proxy if client credentials and domain are available
                if (!string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(clientSecret) && !string.IsNullOrEmpty(cognitoDomain))
                {
                    var defaultProxyOptions = new OAuthProxyOptions
                    {
                        BaseUrl = "http://localhost:5002",
                        UpstreamClientId = clientId,
                        UpstreamClientSecret = clientSecret,
                        UpstreamAuthorizationEndpoint = $"https://{cognitoDomain}/oauth2/authorize",
                        UpstreamTokenEndpoint = $"https://{cognitoDomain}/oauth2/token",
                        UpstreamRevocationEndpoint = $"https://{cognitoDomain}/oauth2/revoke",
                        ValidScopes = requiredScopes?.ToList() ?? new List<string> 
                        { 
                            "openid", 
                            "profile", 
                            "email" 
                        }
                    };

                    var clientStore = new InMemoryClientStore();
                    var clientRegistration = new OAuthClientRegistration
                    {
                        ClientId = clientId,
                        ClientSecret = clientSecret,
                        RedirectUris = new List<string> { "http://localhost:5002/auth/callback" },
                        AllowedRedirectUriPatterns = new List<string> { "http://localhost:*/auth/callback" }
                    };
                    clientStore.StoreClientAsync(clientId, clientRegistration).GetAwaiter().GetResult();

                    builder.WithOAuthProxy(defaultProxyOptions, tokenVerifier, clientStore);
                    logger?.LogInformation("AWS Cognito OAuth Proxy configured successfully");
                }

            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Failed to configure AWS Cognito token verifier authentication");
                throw;
            }
        }
        else
        {
            logger?.LogWarning(
                "AWS Cognito token verifier authentication: Credentials not found. " +
                "Set FASTMCP_SERVER_AUTH_AWSCOGNITO_USER_POOL_ID and FASTMCP_SERVER_AUTH_AWSCOGNITO_REGION " +
                "environment variables to enable authentication.");
        }

        return builder;
    }

    public static McpServerBuilder AddAuth0TokenVerifier(
        this McpServerBuilder builder,
        Auth0AuthOptions? options = null)
    {
        var config = builder.GetWebAppBuilder().Configuration;
        var services = builder.GetWebAppBuilder().Services; // Get the IServiceCollection
        var logger = services.BuildServiceProvider().GetService<ILogger>(); // Use services here

        var domain = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AUTH0_DOMAIN", "Auth0:Domain");
        var audience = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AUTH0_AUDIENCE", "Auth0:Audience");
        var clientId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AUTH0_CLIENT_ID", "Auth0:ClientId");
        var clientSecret = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AUTH0_CLIENT_SECRET", "Auth0:ClientSecret");
        var requiredScopes = options?.RequiredScopes;

        if (!string.IsNullOrEmpty(domain) && !string.IsNullOrEmpty(audience))
        {
            logger?.LogInformation("Auth0 token verifier authentication: Credentials detected, configuring provider...");

            try
            {
                var tokenVerifier = new Auth0TokenVerifier(
                    configUrl: domain,
                    audience: audience,
                    requiredScopes: requiredScopes,
                    logger: logger as ILogger<Auth0TokenVerifier>);

                // Register the ITokenVerifier instance with the service collection
                services.AddSingleton<ITokenVerifier>(tokenVerifier); 

                builder.WithAuthentication(authBuilder =>
                {
                    authBuilder.AddTokenVerifier("Auth0", tokenVerifier);
                });

                SetDefaultChallengeScheme(builder, "Auth0");
                logger?.LogInformation("Auth0 token verifier authentication configured successfully");

                // Configure OAuth Proxy if client credentials are available
                if (!string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(clientSecret))
                {
                    var defaultProxyOptions = new OAuthProxyOptions
                    {
                        BaseUrl = "http://localhost:5002",
                        UpstreamClientId = clientId,
                        UpstreamClientSecret = clientSecret,
                        UpstreamAuthorizationEndpoint = $"https://{domain}/authorize",
                        UpstreamTokenEndpoint = $"https://{domain}/oauth/token",
                        UpstreamRevocationEndpoint = $"https://{domain}/oauth/revoke",
                        ValidScopes = requiredScopes?.ToList() ?? new List<string> 
                        { 
                            "openid", 
                            "profile", 
                            "email", 
                            "offline_access" 
                        }
                    };

                    var clientStore = new InMemoryClientStore();
                    var clientRegistration = new OAuthClientRegistration
                    {
                        ClientId = clientId,
                        ClientSecret = clientSecret,
                        RedirectUris = new List<string> { "http://localhost:5002/auth/callback" },
                        AllowedRedirectUriPatterns = new List<string> { "http://localhost:*/auth/callback" }
                    };
                    clientStore.StoreClientAsync(clientId, clientRegistration).GetAwaiter().GetResult();

                    builder.WithOAuthProxy(defaultProxyOptions, tokenVerifier, clientStore);
                    logger?.LogInformation("Auth0 OAuth Proxy configured successfully");
                }

            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Failed to configure Auth0 token verifier authentication");
                throw;
            }
        }
        else
        {
            logger?.LogWarning(
                "Auth0 token verifier authentication: Credentials not found. " +
                "Set FASTMCP_SERVER_AUTH_AUTH0_DOMAIN and FASTMCP_SERVER_AUTH_AUTH0_AUDIENCE " +
                "environment variables to enable authentication.");
        }

        return builder;
    }

    public static McpServerBuilder AddOktaTokenVerifier(
        this McpServerBuilder builder,
        OktaAuthOptions? options = null)
    {
        var config = builder.GetWebAppBuilder().Configuration;
        var services = builder.GetWebAppBuilder().Services; // Get the IServiceCollection
        var logger = services.BuildServiceProvider().GetService<ILogger>(); // Use services here

        var domain = GetConfigValue(config, "FASTMCP_SERVER_AUTH_OKTA_DOMAIN", "Okta:Domain");
        var audience = GetConfigValue(config, "FASTMCP_SERVER_AUTH_OKTA_AUDIENCE", "Okta:Audience");
        var clientId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_OKTA_CLIENT_ID", "Okta:ClientId");
        var clientSecret = GetConfigValue(config, "FASTMCP_SERVER_AUTH_OKTA_CLIENT_SECRET", "Okta:ClientSecret");
        var requiredScopes = options?.RequiredScopes;

        if (!string.IsNullOrEmpty(domain) && !string.IsNullOrEmpty(audience))
        {
            logger?.LogInformation("Okta token verifier authentication: Credentials detected, configuring provider...");

            try
            {
                var tokenVerifier = new OktaTokenVerifier(
                    oktaDomain: domain,
                    audience: audience,
                    requiredScopes: requiredScopes,
                    logger: logger as ILogger<OktaTokenVerifier>);

                // Register the ITokenVerifier instance with the service collection
                services.AddSingleton<ITokenVerifier>(tokenVerifier); 

                builder.WithAuthentication(authBuilder =>
                {
                    authBuilder.AddTokenVerifier("Okta", tokenVerifier);
                });

                SetDefaultChallengeScheme(builder, "Okta");
                logger?.LogInformation("Okta token verifier authentication configured successfully");

                // Configure OAuth Proxy if client credentials are available
                if (!string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(clientSecret))
                {
                    var defaultProxyOptions = new OAuthProxyOptions
                    {
                        BaseUrl = "http://localhost:5002",
                        UpstreamClientId = clientId,
                        UpstreamClientSecret = clientSecret,
                        UpstreamAuthorizationEndpoint = $"https://{domain}/oauth2/default/v1/authorize",
                        UpstreamTokenEndpoint = $"https://{domain}/oauth2/default/v1/token",
                        UpstreamRevocationEndpoint = $"https://{domain}/oauth2/default/v1/revoke",
                        ValidScopes = requiredScopes?.ToList() ?? new List<string> 
                        { 
                            "openid", 
                            "profile", 
                            "email", 
                            "offline_access" 
                        }
                    };

                    var clientStore = new InMemoryClientStore();
                    var clientRegistration = new OAuthClientRegistration
                    {
                        ClientId = clientId,
                        ClientSecret = clientSecret,
                        RedirectUris = new List<string> { "http://localhost:5002/auth/callback" },
                        AllowedRedirectUriPatterns = new List<string> { "http://localhost:*/auth/callback" }
                    };
                    clientStore.StoreClientAsync(clientId, clientRegistration).GetAwaiter().GetResult();

                    builder.WithOAuthProxy(defaultProxyOptions, tokenVerifier, clientStore);
                    logger?.LogInformation("Okta OAuth Proxy configured successfully");
                }

            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Failed to configure Okta token verifier authentication");
                throw;
            }
        }
        else
        {
            logger?.LogWarning(
                "Okta token verifier authentication: Credentials not found. " +
                "Set FASTMCP_SERVER_AUTH_OKTA_DOMAIN and FASTMCP_SERVER_AUTH_OKTA_AUDIENCE " +
                "environment variables to enable authentication.");
        }

        return builder;
    }

    public static McpServerBuilder AddCustomTokenVerifier<TVerifier>(
        this McpServerBuilder builder,
        string schemeName)
        where TVerifier : class, ITokenVerifier
    {
        var services = builder.GetWebAppBuilder().Services; // Get the IServiceCollection
        var logger = services.BuildServiceProvider().GetService<ILogger>(); // Use services here
        
        // This method expects the TVerifier to be registered directly by the consumer
        // if it has specific constructor dependencies. For simplicity, we assume
        // a parameterless constructor or one resolvable by DI here.

        // Register the custom ITokenVerifier with the service collection.
        // If the verifier has complex dependencies, it should be registered
        // by the consumer before calling this method, and this part could be
        // updated to resolve it from services.
        services.AddSingleton<ITokenVerifier, TVerifier>();

        builder.WithAuthentication(authBuilder =>
        {
            // Resolve the registered ITokenVerifier instance
            var tokenVerifier = services.BuildServiceProvider().GetRequiredService<ITokenVerifier>();
            authBuilder.AddTokenVerifier(schemeName, tokenVerifier);
        });

        SetDefaultChallengeScheme(builder, schemeName);
        logger?.LogInformation($"Custom token verifier '{schemeName}' authentication configured successfully");

        return builder;
    }

    /// <summary>
    /// Configures Okta authentication using token verifier.
    /// </summary>
    public static McpServerBuilder AddOkta(
        this McpServerBuilder builder,
        OktaAuthOptions? options = null)
    {
        var config = builder.GetWebAppBuilder().Configuration;
        var logger = builder.GetWebAppBuilder().Services.BuildServiceProvider().GetService<ILogger>();
        
        var domain = GetConfigValue(config, "FASTMCP_SERVER_AUTH_OKTA_DOMAIN", "Okta:Domain");
        var clientId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_OKTA_CLIENT_ID", "Okta:ClientId");
        var clientSecret = GetConfigValue(config, "FASTMCP_SERVER_AUTH_OKTA_CLIENT_SECRET", "Okta:ClientSecret");
        var audience = options?.Audience;
        var requiredScopes = options?.RequiredScopes;
        var timeoutSeconds = options?.TimeoutSeconds ?? 10;
        var useIntrospection = options?.UseIntrospection ?? false;

        if (!string.IsNullOrEmpty(domain))
        {
            logger?.LogInformation("Okta token verifier authentication: Credentials detected, configuring provider...");

            try
            {
                ITokenVerifier tokenVerifier;
                if (useIntrospection && !string.IsNullOrEmpty(clientSecret))
                {
                    tokenVerifier = new OktaTokenVerifier(
                        oktaDomain: domain,
                        clientId: clientId ?? string.Empty,
                        clientSecret: clientSecret,
                        audience: audience,
                        requiredScopes: requiredScopes,
                        timeoutSeconds: timeoutSeconds,
                        logger: logger as ILogger<OktaTokenVerifier>,
                        useIntrospection: true);
                }
                else
                {
                    tokenVerifier = new OktaTokenVerifier(
                        oktaDomain: domain,
                        audience: audience,
                        requiredScopes: requiredScopes,
                        logger: logger as ILogger<OktaTokenVerifier>);
                }

                builder.WithAuthentication(authBuilder =>
                {
                    authBuilder.AddTokenVerifier("Okta", tokenVerifier);
                });

                SetDefaultChallengeScheme(builder, "Okta");
                logger?.LogInformation("Okta token verifier authentication configured successfully");
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Failed to configure Okta token verifier authentication");
                throw;
            }
        }
        else
        {
            logger?.LogWarning(
                "Okta token verifier authentication: Credentials not found. " +
                "Set FASTMCP_SERVER_AUTH_OKTA_DOMAIN environment variable to enable authentication.");
        }

        return builder;
    }

    /// <summary>
    /// Configures Auth0 authentication using token verifier.
    /// </summary>
    public static McpServerBuilder AddAuth0(
        this McpServerBuilder builder,
        Auth0AuthOptions? options = null)
    {
        var config = builder.GetWebAppBuilder().Configuration;
        var logger = builder.GetWebAppBuilder().Services.BuildServiceProvider().GetService<ILogger>();

        var domain = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AUTH0_DOMAIN", "Auth0:Domain");
        var clientId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AUTH0_CLIENT_ID", "Auth0:ClientId");
        var clientSecret = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AUTH0_CLIENT_SECRET", "Auth0:ClientSecret");

        if (!string.IsNullOrEmpty(domain) && !string.IsNullOrEmpty(clientId))
        {
            logger?.LogInformation("Auth0 authentication: Credentials detected, configuring provider...");

            try
            {
                var configUrl = domain.StartsWith("http") ? domain : $"https://{domain}";
                var auth0TokenVerifier = new Auth0TokenVerifier(
                    configUrl: configUrl,
                    audience: clientId,
                    requiredScopes: null,
                    logger: logger as ILogger<Auth0TokenVerifier>);

                builder.WithAuthentication(auth =>
                {
                    auth.AddTokenVerifier("Auth0", auth0TokenVerifier);
                });
                
                SetDefaultChallengeScheme(builder, "Auth0");

                logger?.LogInformation("Auth0 authentication configured successfully");
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Failed to configure Auth0 authentication");
                throw;
            }
        }
        else
        {
            logger?.LogWarning(
                "Auth0 authentication: Credentials not found. " +
                "Set FASTMCP_SERVER_AUTH_AUTH0_DOMAIN and FASTMCP_SERVER_AUTH_AUTH0_CLIENT_ID " +
                "environment variables to enable authentication.");
        }

        return builder;
    }

    /// <summary>
    /// Configures AWS Cognito authentication using token verifier.
    /// </summary>
    public static McpServerBuilder AddAwsCognito(
        this McpServerBuilder builder,
        AwsCognitoAuthOptions? options = null)
    {
        var config = builder.GetWebAppBuilder().Configuration;
        var logger = builder.GetWebAppBuilder().Services.BuildServiceProvider().GetService<ILogger>();
        
        var userPoolId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_COGNITO_USER_POOL_ID", "AwsCognito:UserPoolId");
        var awsRegion = GetConfigValue(config, "FASTMCP_SERVER_AUTH_COGNITO_AWS_REGION", "AwsCognito:AwsRegion") ?? "us-east-1";
        var audience = options?.Audience;
        var requiredScopes = options?.RequiredScopes;

        if (!string.IsNullOrEmpty(userPoolId))
        {
            logger?.LogInformation("AWS Cognito token verifier authentication: Credentials detected, configuring provider...");

            try
            {
                var tokenVerifier = new AwsCognitoTokenVerifier(
                    userPoolId: userPoolId,
                    awsRegion: awsRegion,
                    audience: audience,
                    requiredScopes: requiredScopes,
                    logger: logger as ILogger<AwsCognitoTokenVerifier>);

                builder.WithAuthentication(authBuilder =>
                {
                    authBuilder.AddTokenVerifier("AwsCognito", tokenVerifier);
                });

                SetDefaultChallengeScheme(builder, "AwsCognito");
                logger?.LogInformation("AWS Cognito token verifier authentication configured successfully");
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Failed to configure AWS Cognito token verifier authentication");
                throw;
            }
        }
        else
        {
            logger?.LogWarning(
                "AWS Cognito token verifier authentication: Credentials not found. " +
                "Set FASTMCP_SERVER_AUTH_COGNITO_USER_POOL_ID environment variable to enable authentication.");
        }

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
        OAuthProxyOptions? proxyOptions = null,
        GoogleAuthOptions? googleAuthOptions = null)
    {
        var config = builder.GetWebAppBuilder().Configuration;
        var services = builder.GetWebAppBuilder().Services; // Get the IServiceCollection
        var logger = services.BuildServiceProvider().GetService<ILogger>(); // Use services here

        var clientId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID", "Google:ClientId");
        var clientSecret = GetConfigValue(config, "FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET", "Google:ClientSecret");
        var requiredScopes = googleAuthOptions?.RequiredScopes;

        if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
        {
            logger?.LogWarning(
                "Google OAuth proxy authentication: Credentials not found. " +
                "Set FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID and FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET " +
                "environment variables to enable authentication.");
            return builder;
        }

        var defaultProxyOptions = proxyOptions ?? new OAuthProxyOptions();
        defaultProxyOptions.UpstreamAuthorizationEndpoint = defaultProxyOptions.UpstreamAuthorizationEndpoint ?? "https://accounts.google.com/o/oauth2/v2/auth";
        defaultProxyOptions.UpstreamTokenEndpoint = defaultProxyOptions.UpstreamTokenEndpoint ?? "https://oauth2.googleapis.com/token";
        defaultProxyOptions.UpstreamClientId = clientId;
        defaultProxyOptions.UpstreamClientSecret = clientSecret;

        var tokenVerifier = new GoogleTokenVerifier(
            clientId: clientId,
            requiredScopes: requiredScopes,
            logger: logger as ILogger<GoogleTokenVerifier>);
        
        // Register the ITokenVerifier instance with the service collection
        services.AddSingleton<ITokenVerifier>(tokenVerifier); 

        return builder.WithOAuthProxy(defaultProxyOptions, tokenVerifier);
    }

    /// <summary>
    /// Configures OAuth Proxy for GitHub (non-DCR provider).
    /// </summary>
    public static McpServerBuilder AddGitHubOAuthProxy(
        this McpServerBuilder builder,
        OAuthProxyOptions? proxyOptions = null,
        GitHubAuthOptions? githubAuthOptions = null)
    {
        var config = builder.GetWebAppBuilder().Configuration;
        var services = builder.GetWebAppBuilder().Services; // Get the IServiceCollection
        var logger = services.BuildServiceProvider().GetService<ILogger>(); // Use services here

        var clientId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_GITHUB_CLIENT_ID", "GitHub:ClientId");
        var clientSecret = GetConfigValue(config, "FASTMCP_SERVER_AUTH_GITHUB_CLIENT_SECRET", "GitHub:ClientSecret");
        var requiredScopes = githubAuthOptions?.RequiredScopes;

        if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
        {
            logger?.LogWarning(
                "GitHub OAuth proxy authentication: Credentials not found. " +
                "Set FASTMCP_SERVER_AUTH_GITHUB_CLIENT_ID and FASTMCP_SERVER_AUTH_GITHUB_CLIENT_SECRET " +
                "environment variables to enable authentication.");
            return builder;
        }

        var defaultProxyOptions = proxyOptions ?? new OAuthProxyOptions();
        defaultProxyOptions.UpstreamAuthorizationEndpoint = defaultProxyOptions.UpstreamAuthorizationEndpoint ?? "https://github.com/login/oauth/authorize";
        defaultProxyOptions.UpstreamTokenEndpoint = defaultProxyOptions.UpstreamTokenEndpoint ?? "https://github.com/login/oauth/access_token";
        defaultProxyOptions.UpstreamClientId = clientId;
        defaultProxyOptions.UpstreamClientSecret = clientSecret;

        var tokenVerifier = new GitHubTokenVerifier(
            requiredScopes: requiredScopes,
            logger: logger as ILogger<GitHubTokenVerifier>);

        // Register the ITokenVerifier instance with the service collection
        services.AddSingleton<ITokenVerifier>(tokenVerifier);

        return builder.WithOAuthProxy(defaultProxyOptions, tokenVerifier);
    }

    /// <summary>
    /// Configures OAuth Proxy for Azure AD (non-DCR provider).
    /// </summary>
    public static McpServerBuilder AddAzureAdOAuthProxy(
        this McpServerBuilder builder,
        OAuthProxyOptions? proxyOptions = null,
        AzureAdAuthOptions? azureAdAuthOptions = null)
    {
        var config = builder.GetWebAppBuilder().Configuration;
        var services = builder.GetWebAppBuilder().Services; 
        
        services.AddLogging(); 
        var serviceProvider = services.BuildServiceProvider(); 
        var loggerFactory = serviceProvider.GetRequiredService<ILoggerFactory>();
        
        var extensionLogger = loggerFactory.CreateLogger(typeof(McpAuthenticationExtensions).FullName!);
        var azureAdTokenVerifierLogger = loggerFactory.CreateLogger<AzureAdTokenVerifier>();

        // --- DIAGNOSTIC LOG: Entering method ---
        extensionLogger.LogDebug("[AzureAdOAuthProxy] Entering AddAzureAdOAuthProxy method.");

        var tenantId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AZUREAD_TENANT_ID", "AzureAd:TenantId");
        var clientId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AZUREAD_CLIENT_ID", "AzureAd:ClientId");
        var clientSecret = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AZUREAD_CLIENT_SECRET", "AzureAd:ClientSecret");
        var baseAuthority = azureAdAuthOptions?.BaseAuthority ?? "login.microsoftonline.com";
        var requiredScopes = azureAdAuthOptions?.RequiredScopes;

        // --- DIAGNOSTIC LOG: Configuration values ---
        extensionLogger.LogDebug($"[AzureAdOAuthProxy] Config Values: TenantId='{tenantId}', ClientId='{clientId}', ClientSecret='{(string.IsNullOrEmpty(clientSecret) ? "[NOT SET]" : "[SET]")}', BaseAuthority='{baseAuthority}'");

        if (string.IsNullOrEmpty(tenantId) || string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
        {
            extensionLogger.LogWarning(
                "Azure AD OAuth proxy authentication: Credentials not found. " +
                "Set FASTMCP_SERVER_AUTH_AZUREAD_TENANT_ID, FASTMCP_SERVER_AUTH_AZUREAD_CLIENT_ID and FASTMCP_SERVER_AUTH_AZUREAD_CLIENT_SECRET " +
                "environment variables to enable authentication. Method will exit early."); // --- DIAGNOSTIC LOG: Early Exit Reason ---
            return builder; // Early exit
        }

        var defaultProxyOptions = proxyOptions ?? new OAuthProxyOptions();
        defaultProxyOptions.UpstreamAuthorizationEndpoint = defaultProxyOptions.UpstreamAuthorizationEndpoint ?? $"https://{baseAuthority}/{tenantId}/oauth2/v2.0/authorize";
        defaultProxyOptions.UpstreamTokenEndpoint = defaultProxyOptions.UpstreamTokenEndpoint ?? $"https://{baseAuthority}/{tenantId}/oauth2/v2.0/token";
        defaultProxyOptions.UpstreamClientId = clientId;
        defaultProxyOptions.UpstreamClientSecret = clientSecret;

        var tokenVerifier = new AzureAdTokenVerifier(
            tenantId: tenantId,
            clientId: clientId,
            requiredScopes: requiredScopes,
            baseAuthority: baseAuthority,
            logger: azureAdTokenVerifierLogger); 

        try
        {
            services.AddSingleton<ITokenVerifier>(tokenVerifier); 
            extensionLogger.LogDebug($"[AzureAdOAuthProxy] Successfully registered ITokenVerifier for scheme 'AzureAd' of type {tokenVerifier.GetType().Name}.");
        }
        catch (Exception ex)
        {
            extensionLogger.LogError(ex, "[AzureAdOAuthProxy] CRITICAL ERROR: Failed to register ITokenVerifier for scheme 'AzureAd'. This will cause authentication failures.");
            throw; 
        }

        extensionLogger.LogDebug("[AzureAdOAuthProxy] Calling builder.WithOAuthProxy."); // --- DIAGNOSTIC LOG: Before WithOAuthProxy ---
        return builder.WithOAuthProxy(defaultProxyOptions, tokenVerifier); 
    }

    /// <summary>
    /// Configures OAuth Proxy for AWS Cognito (non-DCR provider).
    /// </summary>
    public static McpServerBuilder AddAwsCognitoOAuthProxy(
        this McpServerBuilder builder,
        OAuthProxyOptions? proxyOptions = null,
        AwsCognitoAuthOptions? awsCognitoAuthOptions = null)
    {
        var config = builder.GetWebAppBuilder().Configuration;
        var services = builder.GetWebAppBuilder().Services; // Get the IServiceCollection
        var logger = services.BuildServiceProvider().GetService<ILogger>(); // Use services here

        var userPoolId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AWSCOGNITO_USER_POOL_ID", "AwsCognito:UserPoolId");
        var region = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AWSCOGNITO_REGION", "AwsCognito:Region");
        var clientId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AWSCOGNITO_CLIENT_ID", "AwsCognito:ClientId");
        var clientSecret = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AWSCOGNITO_CLIENT_SECRET", "AwsCognito:ClientSecret");
        var requiredScopes = awsCognitoAuthOptions?.RequiredScopes;

        if (string.IsNullOrEmpty(userPoolId) || string.IsNullOrEmpty(region) || string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
        {
            logger?.LogWarning(
                "AWS Cognito OAuth proxy authentication: Credentials not found. " +
                "Set FASTMCP_SERVER_AUTH_AWSCOGNITO_USER_POOL_ID, FASTMCP_SERVER_AUTH_AWSCOGNITO_REGION, " +
                "FASTMCP_SERVER_AUTH_AWSCOGNITO_CLIENT_ID and FASTMCP_SERVER_AUTH_AWSCOGNITO_CLIENT_SECRET " +
                "environment variables to enable authentication.");
            return builder;
        }

        var domain = $"https://{awsCognitoAuthOptions?.ClientId ?? "your-cognito-domain"}.auth.{region}.amazoncognito.com";

        var defaultProxyOptions = proxyOptions ?? new OAuthProxyOptions();
        defaultProxyOptions.UpstreamAuthorizationEndpoint = defaultProxyOptions.UpstreamAuthorizationEndpoint ?? $"{domain}/oauth2/authorize";
        defaultProxyOptions.UpstreamTokenEndpoint = defaultProxyOptions.UpstreamTokenEndpoint ?? $"{domain}/oauth2/token";
        defaultProxyOptions.UpstreamClientId = clientId;
        defaultProxyOptions.UpstreamClientSecret = clientSecret;

        var tokenVerifier = new AwsCognitoTokenVerifier(
            userPoolId: userPoolId,
            awsRegion: region,
            requiredScopes: requiredScopes,
            logger: logger as ILogger<AwsCognitoTokenVerifier>);

        // Register the ITokenVerifier instance with the service collection
        services.AddSingleton<ITokenVerifier>(tokenVerifier);

        return builder.WithOAuthProxy(defaultProxyOptions, tokenVerifier);
    }

    /// <summary>
    /// Configures OAuth Proxy for Auth0 (non-DCR provider).
    /// </summary>
    public static McpServerBuilder AddAuth0OAuthProxy(
        this McpServerBuilder builder,
        OAuthProxyOptions? proxyOptions = null,
        Auth0AuthOptions? auth0AuthOptions = null)
    {
        var config = builder.GetWebAppBuilder().Configuration;
        var services = builder.GetWebAppBuilder().Services; // Get the IServiceCollection
        var logger = services.BuildServiceProvider().GetService<ILogger>(); // Use services here

        var domain = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AUTH0_DOMAIN", "Auth0:Domain");
        var clientId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AUTH0_CLIENT_ID", "Auth0:ClientId");
        var clientSecret = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AUTH0_CLIENT_SECRET", "Auth0:ClientSecret");
        var audience = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AUTH0_AUDIENCE", "Auth0:Audience");
        var requiredScopes = auth0AuthOptions?.RequiredScopes;
        var configUrl = GetConfigValue(config, "FASTMCP_SERVER_AUTH_AUTH0_CONFIG_URL", "Auth0:ConfigUrl");

        if (string.IsNullOrEmpty(domain) || string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret) || string.IsNullOrEmpty(audience))
        {
            logger?.LogWarning(
                "Auth0 OAuth proxy authentication: Credentials not found. " +
                "Set FASTMCP_SERVER_AUTH_AUTH0_DOMAIN, FASTMCP_SERVER_AUTH_AUTH0_CLIENT_ID, " +
                "FASTMCP_SERVER_AUTH_AUTH0_CLIENT_SECRET, and FASTMCP_SERVER_AUTH_AUTH0_AUDIENCE " +
                "environment variables to enable authentication.");
            return builder;
        }

        if (string.IsNullOrEmpty(configUrl) || 
            !Uri.TryCreate(configUrl, UriKind.Absolute, out var uriResult) || 
            (uriResult.Scheme != Uri.UriSchemeHttp && uriResult.Scheme != Uri.UriSchemeHttps) ||
            !configUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Auth0 ConfigUrl must be a valid HTTPS URL.");
        }

        var defaultProxyOptions = proxyOptions ?? new OAuthProxyOptions();
        defaultProxyOptions.UpstreamAuthorizationEndpoint = defaultProxyOptions.UpstreamAuthorizationEndpoint ?? $"{domain}/authorize";
        defaultProxyOptions.UpstreamTokenEndpoint = defaultProxyOptions.UpstreamTokenEndpoint ?? $"{domain}/oauth/token";
        defaultProxyOptions.UpstreamClientId = clientId;
        defaultProxyOptions.UpstreamClientSecret = clientSecret;

        var tokenVerifier = new Auth0TokenVerifier(
            configUrl: domain,
            audience: audience,
            requiredScopes: requiredScopes,
            logger: logger as ILogger<Auth0TokenVerifier>);

        // Register the ITokenVerifier instance with the service collection
        services.AddSingleton<ITokenVerifier>(tokenVerifier);

        return builder.WithOAuthProxy(defaultProxyOptions, tokenVerifier);
    }

     /// <summary>
    /// Configures OAuth Proxy for Okta (non-DCR provider).
    /// </summary>
    public static McpServerBuilder AddOktaOAuthProxy(
        this McpServerBuilder builder,
        OAuthProxyOptions? proxyOptions = null,
        OktaAuthOptions? oktaAuthOptions = null)
    {
        var config = builder.GetWebAppBuilder().Configuration;
        var services = builder.GetWebAppBuilder().Services; // Get the IServiceCollection
        var logger = services.BuildServiceProvider().GetService<ILogger>(); // Use services here

        var domain = GetConfigValue(config, "FASTMCP_SERVER_AUTH_OKTA_DOMAIN", "Okta:Domain");
        var clientId = GetConfigValue(config, "FASTMCP_SERVER_AUTH_OKTA_CLIENT_ID", "Okta:ClientId");
        var clientSecret = GetConfigValue(config, "FASTMCP_SERVER_AUTH_OKTA_CLIENT_SECRET", "Okta:ClientSecret");
        var audience = GetConfigValue(config, "FASTMCP_SERVER_AUTH_OKTA_AUDIENCE", "Okta:Audience");
        var requiredScopes = oktaAuthOptions?.RequiredScopes;

        if (string.IsNullOrEmpty(domain) || string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret) || string.IsNullOrEmpty(audience))
        {
            logger?.LogWarning(
                "Okta OAuth proxy authentication: Credentials not found. " +
                "Set FASTMCP_SERVER_AUTH_OKTA_DOMAIN, FASTMCP_SERVER_AUTH_OKTA_CLIENT_ID, " +
                "FASTMCP_SERVER_AUTH_OKTA_CLIENT_SECRET, and FASTMCP_SERVER_AUTH_OKTA_AUDIENCE " +
                "environment variables to enable authentication.");
            return builder;
        }
        if (string.IsNullOrEmpty(domain))
            throw new InvalidOperationException("Okta Domain is required");

        var defaultProxyOptions = proxyOptions ?? new OAuthProxyOptions();
        defaultProxyOptions.UpstreamAuthorizationEndpoint = defaultProxyOptions.UpstreamAuthorizationEndpoint ?? $"{domain}/oauth2/default/v1/authorize";
        defaultProxyOptions.UpstreamTokenEndpoint = defaultProxyOptions.UpstreamTokenEndpoint ?? $"{domain}/oauth2/default/v1/token";
        defaultProxyOptions.UpstreamClientId = clientId;
        defaultProxyOptions.UpstreamClientSecret = clientSecret;

        var tokenVerifier = new OktaTokenVerifier(
            oktaDomain: domain,
            audience: audience,
            requiredScopes: requiredScopes,
            logger: logger as ILogger<OktaTokenVerifier>);

        // Register the ITokenVerifier instance with the service collection
        services.AddSingleton<ITokenVerifier>(tokenVerifier);

        return builder.WithOAuthProxy(defaultProxyOptions, tokenVerifier);
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

    /// <summary>
    /// Helper method to get configuration value from environment variable or appsettings.
    /// </summary>
    private static string? GetConfigValue(IConfiguration config, string envVarName, string configPath)
    {
        // Priority 1: Environment variable
        var envValue = Environment.GetEnvironmentVariable(envVarName);
        if (!string.IsNullOrEmpty(envValue))
        {
            return envValue;
        }

        // Priority 2: appsettings.json
        var configValue = config[configPath];
        if (!string.IsNullOrEmpty(configValue))
        {
            return configValue;
        }

        return null;
    }
}