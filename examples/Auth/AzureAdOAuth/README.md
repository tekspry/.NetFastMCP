# Azure AD OAuth Example

Demonstrates FastMCP server protection with Azure AD (Microsoft Entra) OAuth.

## Setup

### 1. Azure App Registration

1. Go to [Azure Portal → App registrations](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade)
2. Click **New registration**
3. Configure:
   - Name: Your app name
   - Supported account types: Choose based on your needs
   - Redirect URI: `http://localhost:5002/auth/callback` (Web platform)
4. Go to **Certificates & secrets** → **New client secret**
5. Note from **Overview**:
   - Application (client) ID
   - Directory (tenant) ID

### 2. Configuration

Set environment variables:

```powershell
# Windows PowerShell
$env:FASTMCP_SERVER_AUTH_AZUREAD_TENANT_ID="your-tenant-id"
$env:FASTMCP_SERVER_AUTH_AZUREAD_CLIENT_ID="your-client-id"
$env:FASTMCP_SERVER_AUTH_AZUREAD_CLIENT_SECRET="your-client-secret"
```

```bash
# Linux/Mac
export FASTMCP_SERVER_AUTH_AZUREAD_TENANT_ID="your-tenant-id"
export FASTMCP_SERVER_AUTH_AZUREAD_CLIENT_ID="your-client-id"
export FASTMCP_SERVER_AUTH_AZUREAD_CLIENT_SECRET="your-client-secret"
```

### 3. Run the Server

```bash
cd examples/Auth/AzureAdOAuth
dotnet run
```

The server will start on `http://localhost:5002` with:
- MCP endpoint: `http://localhost:5002/mcp`
- OAuth callback: `http://localhost:5002/auth/callback`
- OAuth discovery: `http://localhost:5002/.well-known/oauth-authorization-server`

### 4. Test with MCP Client

MCP clients can automatically discover the authentication requirements and initiate the OAuth flow. The OAuth Proxy handles:
- Dynamic Client Registration (DCR)
- Authorization code flow with PKCE
- Token exchange and validation

### 5. Test with REST Client

Open `azure-ad-auth-tests.rest` in VS Code with the REST Client extension to test the complete OAuth flow manually.

## Features Demonstrated

- **OAuth Proxy Pattern**: Enables DCR for Azure AD
- **Token Verification**: Validates Azure AD JWT tokens
- **Protected Tools**: Tools with `[Authorize]` attribute require authentication
- **User Claims**: Access authenticated user information
- **Default Scopes**: Automatically includes `openid`, `profile`, `email`, `offline_access`