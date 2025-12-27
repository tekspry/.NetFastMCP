# GitHub OAuth Example

Demonstrates FastMCP server protection with GitHub OAuth using OAuth Proxy pattern.

## Setup

### 1. Create GitHub OAuth App

1. Go to [GitHub Settings → Developer settings → OAuth Apps](https://github.com/settings/developers)
2. Click **New OAuth App**
3. Configure:
   - Application name: Your app name
   - Homepage URL: `http://localhost:5001`
   - Authorization callback URL: `http://localhost:5001/auth/callback`
4. Click **Register application**
5. Click **Generate a new client secret**
6. Copy the **Client ID** and **Client Secret**

### 2. Configuration

Set environment variables:

```powershell
# Windows PowerShell
$env:FASTMCP_SERVER_AUTH_GITHUB_CLIENT_ID="your-github-client-id"
$env:FASTMCP_SERVER_AUTH_GITHUB_CLIENT_SECRET="your-github-client-secret"
```

```bash
# Linux/Mac
export FASTMCP_SERVER_AUTH_GITHUB_CLIENT_ID="your-github-client-id"
export FASTMCP_SERVER_AUTH_GITHUB_CLIENT_SECRET="your-github-client-secret"
```

### 3. Run the Server

```bash
cd examples/Auth/GitHubOAuth
dotnet run
```

The server will start on `http://localhost:5001` with:
- MCP endpoint: `http://localhost:5001/mcp`
- OAuth callback: `http://localhost:5001/auth/callback`
- OAuth discovery: `http://localhost:5001/.well-known/oauth-authorization-server`

### 4. Test with MCP Client

MCP clients can automatically discover the authentication requirements and initiate the OAuth flow. The OAuth Proxy handles:
- Dynamic Client Registration (DCR)
- Authorization code flow with PKCE
- Token exchange and validation

### 5. Test with REST Client

Open `github-oauth-tests.rest` in VS Code with the REST Client extension to test the complete OAuth flow manually.

## Features Demonstrated

- **OAuth Proxy Pattern**: Enables DCR for GitHub OAuth
- **Token Verification**: Validates GitHub OAuth tokens
- **Protected Tools**: Tools with `[Authorize]` attribute require authentication
- **User Claims**: Access authenticated user information
- **Default Scopes**: Automatically includes `read:user`, `user:email`
