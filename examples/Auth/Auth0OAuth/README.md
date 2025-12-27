# Auth0 OAuth Example

Demonstrates FastMCP server protection with Auth0 OAuth using OAuth Proxy pattern.

## Setup

### 1. Create Auth0 Application

1. Go to [Auth0 Dashboard](https://manage.auth0.com/)
2. Go to **Applications** → **Applications**
3. Click **Create Application**
4. Choose **Regular Web Applications**
5. Configure:
   - Application name: Your app name
   - Allowed Callback URLs: `http://localhost:5005/auth/callback`
   - Allowed Logout URLs: `http://localhost:5005`
6. Note the following values from the **Settings** tab:
   - Domain (e.g., `your-tenant.auth0.com`)
   - Client ID
   - Client Secret

### 2. Create API (for Audience)

1. Go to **Applications** → **APIs**
2. Click **Create API**
3. Configure:
   - Name: Your API name
   - Identifier: `https://your-api-identifier` (this will be your audience)
4. Note the **Identifier** value

### 3. Configuration

Set environment variables:

```powershell
# Windows PowerShell
$env:FASTMCP_SERVER_AUTH_AUTH0_DOMAIN="your-tenant.auth0.com"
$env:FASTMCP_SERVER_AUTH_AUTH0_AUDIENCE="https://your-api-identifier"
$env:FASTMCP_SERVER_AUTH_AUTH0_CLIENT_ID="your-client-id"
$env:FASTMCP_SERVER_AUTH_AUTH0_CLIENT_SECRET="your-client-secret"
```

```bash
# Linux/Mac
export FASTMCP_SERVER_AUTH_AUTH0_DOMAIN="your-tenant.auth0.com"
export FASTMCP_SERVER_AUTH_AUTH0_AUDIENCE="https://your-api-identifier"
export FASTMCP_SERVER_AUTH_AUTH0_CLIENT_ID="your-client-id"
export FASTMCP_SERVER_AUTH_AUTH0_CLIENT_SECRET="your-client-secret"
```

### 4. Run the Server

```bash
cd examples/Auth/Auth0OAuth
dotnet run
```

The server will start on `http://localhost:5005` with:
- MCP endpoint: `http://localhost:5005/mcp`
- OAuth callback: `http://localhost:5005/auth/callback`
- OAuth discovery: `http://localhost:5005/.well-known/oauth-authorization-server`

### 5. Test with MCP Client

MCP clients can automatically discover the authentication requirements and initiate the OAuth flow. The OAuth Proxy handles:
- Dynamic Client Registration (DCR)
- Authorization code flow with PKCE
- Token exchange and validation

### 6. Test with REST Client

Open `auth0-oauth-tests.rest` in VS Code with the REST Client extension to test the complete OAuth flow manually.

## Features Demonstrated

- **OAuth Proxy Pattern**: Enables DCR for Auth0
- **Token Verification**: Validates Auth0 JWT tokens
- **Protected Tools**: Tools with `[Authorize]` attribute require authentication
- **User Claims**: Access authenticated user information
- **Default Scopes**: Automatically includes `openid`, `profile`, `email`, `offline_access`