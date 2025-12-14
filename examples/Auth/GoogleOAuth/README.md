# Google OAuth Example

Demonstrates FastMCP server protection with Google OAuth using OAuth Proxy pattern.

## Setup

### 1. Create Google OAuth 2.0 Client

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create or select a project
3. Go to **APIs & Services** > **Credentials**
4. Click **Create Credentials** > **OAuth 2.0 Client ID**
5. Configure:
   - Application type: **Web application**
   - Name: Your app name
   - Authorized redirect URIs: `http://localhost:5000/auth/callback`
6. Copy the **Client ID** and **Client Secret**

### 2. Configuration

Create an `appsettings.json` file:

{
  "Authentication": {
    "Google": {
      "ClientId": "your-client-id.apps.googleusercontent.com",
      "ClientSecret": "your-client-secret",
      "RequiredScopes": ["openid", "email", "profile"]
    }
  },
  "BaseUrl": "http://localhost:5000"
}Or set environment variables:

# Windows PowerShell
$env:FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
$env:FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET="your-client-secret"

# Linux/Mac
export FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
export FASTMCP_SERVER_AUTH_GOOGLE_CLIENT_SECRET="your-client-secret"### 3. Run the Server

cd examples/Auth/GoogleOAuth
dotnet runThe server will start on `http://localhost:5000` with:
- MCP endpoint: `http://localhost:5000/mcp`
- OAuth callback: `http://localhost:5000/auth/callback`
- OAuth discovery: `http://localhost:5000/.well-known/oauth-authorization-server`

### 4. Test with MCP Client

MCP clients can automatically discover the authentication requirements and initiate the OAuth flow. The OAuth Proxy handles:
- Dynamic Client Registration (DCR)
- Authorization code flow with PKCE
- Token exchange and validation

## Features Demonstrated

- **OAuth Proxy Pattern**: Enables DCR for non-DCR providers
- **Token Verification**: Validates Google OAuth tokens
- **Protected Tools**: Tools with `[Authorize]` attribute require authentication
- **User Claims**: Access authenticated user information