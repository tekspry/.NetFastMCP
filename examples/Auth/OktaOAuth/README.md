# Okta OAuth Example

Demonstrates FastMCP server protection with Okta OAuth using OAuth Proxy pattern.

## Setup

### 1. Create Okta Application

1. Go to [Okta Admin Console](https://admin.okta.com/)
2. Go to **Applications** → **Applications**
3. Click **Create App Integration**
4. Choose **OIDC - OpenID Connect** and **Web Application**
5. Configure:
   - Application name: Your app name
   - Sign-in redirect URIs: `http://localhost:5007/auth/callback`
   - Sign-out redirect URIs: `http://localhost:5007`
6. Note the following values:
   - Okta Domain (e.g., `dev-123456.okta.com`)
   - Client ID
   - Client Secret

### 2. Configuration

Set environment variables:

```powershell
# Windows PowerShell
$env:FASTMCP_SERVER_AUTH_OKTA_DOMAIN="dev-123456.okta.com"
$env:FASTMCP_SERVER_AUTH_OKTA_AUDIENCE="api://default"
$env:FASTMCP_SERVER_AUTH_OKTA_CLIENT_ID="your-client-id"
$env:FASTMCP_SERVER_AUTH_OKTA_CLIENT_SECRET="your-client-secret"
```

```bash
# Linux/Mac
export FASTMCP_SERVER_AUTH_OKTA_DOMAIN="dev-123456.okta.com"
export FASTMCP_SERVER_AUTH_OKTA_AUDIENCE="api://default"
export FASTMCP_SERVER_AUTH_OKTA_CLIENT_ID="your-client-id"
export FASTMCP_SERVER_AUTH_OKTA_CLIENT_SECRET="your-client-secret"
```

### 3. Run the Server

```bash
cd examples/Auth/OktaOAuth
dotnet run
```

The server will start on `http://localhost:5007` with:
- MCP endpoint: `http://localhost:5007/mcp`
- OAuth callback: `http://localhost:5007/auth/callback`
- OAuth discovery: `http://localhost:5007/.well-known/oauth-authorization-server`

### 4. Test with MCP Client

MCP clients can automatically discover the authentication requirements and initiate the OAuth flow. The OAuth Proxy handles:
- Dynamic Client Registration (DCR)
- Authorization code flow with PKCE
- Token exchange and validation

### 5. Test with REST Client

Open `okta-oauth-tests.rest` in VS Code with the REST Client extension to test the complete OAuth flow manually.

## Features Demonstrated

- **OAuth Proxy Pattern**: Enables DCR for Okta
- **Token Verification**: Validates Okta JWT tokens
- **Protected Tools**: Tools with `[Authorize]` attribute require authentication
- **User Claims**: Access authenticated user information
- **Default Scopes**: Automatically includes `openid`, `profile`, `email`, `offline_access`
