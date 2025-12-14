# Okta OAuth Example

Demonstrates FastMCP server protection with Okta OAuth.

## Setup

### 1. Okta Application Setup

1. Go to [Okta Admin Console](https://admin.okta.com/)
2. Go to **Applications** → **Applications**
3. Click **Create App Integration**
4. Choose **OIDC - OpenID Connect** and **Web Application**
5. Configure:
   - Sign-in redirect URIs: `http://localhost:5005/auth/callback`
   - Sign-out redirect URIs: `http://localhost:5005`
6. Note:
   - Domain (e.g., `dev-123456.okta.com`)
   - Client ID
   - Client Secret

### 2. Configuration

Set environment variables:

# Windows PowerShell
$env:FASTMCP_SERVER_AUTH_OKTA_DOMAIN="dev-123456.okta.com"
$env:FASTMCP_SERVER_AUTH_OKTA_CLIENT_ID="your-client-id"
$env:FASTMCP_SERVER_AUTH_OKTA_CLIENT_SECRET="your-client-secret"
$env:FASTMCP_SERVER_AUTH_OKTA_AUDIENCE="api://default"  # Optional

# Linux/Mac
export FASTMCP_SERVER_AUTH_OKTA_DOMAIN="dev-123456.okta.com"
export FASTMCP_SERVER_AUTH_OKTA_CLIENT_ID="your-client-id"
export FASTMCP_SERVER_AUTH_OKTA_CLIENT_SECRET="your-client-secret"
export FASTMCP_SERVER_AUTH_OKTA_AUDIENCE="api://default"### 3. Run

cd examples/Auth/OktaOAuth
dotnet run