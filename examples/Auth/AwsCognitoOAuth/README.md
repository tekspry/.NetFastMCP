# AWS Cognito OAuth Example

Demonstrates FastMCP server protection with AWS Cognito OAuth using OAuth Proxy pattern.

## Setup

### 1. Create AWS Cognito User Pool

1. Go to [AWS Cognito Console](https://console.aws.amazon.com/cognito/)
2. Create a User Pool or use an existing one
3. Configure a **Domain** for your User Pool:
   - Go to **App integration** → **Domain**
   - Choose a domain prefix (e.g., `myapp`)
   - Note the full domain: `myapp.auth.us-east-1.amazoncognito.com`
4. Create an **App Client**:
   - Go to **App integration** → **App clients**
   - Click **Create app client**
   - Configure:
     - App type: **Confidential client**
     - App client name: Your app name
     - Generate client secret: **Yes**
     - Authentication flows: Enable **Authorization code grant**
     - Allowed callback URLs: `http://localhost:5006/auth/callback`
     - Allowed sign-out URLs: `http://localhost:5006`
     - OAuth 2.0 grant types: **Authorization code grant**
     - OpenID Connect scopes: Select `openid`, `profile`, `email`
5. Note the following values:
   - User Pool ID (e.g., `us-east-1_XXXXXXXXX`)
   - AWS Region (e.g., `us-east-1`)
   - App Client ID
   - App Client Secret
   - Cognito Domain (e.g., `myapp.auth.us-east-1.amazoncognito.com`)

### 2. Configuration

Set environment variables:

```powershell
# Windows PowerShell
$env:FASTMCP_SERVER_AUTH_AWSCOGNITO_USER_POOL_ID="us-east-1_XXXXXXXXX"
$env:FASTMCP_SERVER_AUTH_AWSCOGNITO_REGION="us-east-1"
$env:FASTMCP_SERVER_AUTH_AWSCOGNITO_CLIENT_ID="your-app-client-id"
$env:FASTMCP_SERVER_AUTH_AWSCOGNITO_CLIENT_SECRET="your-app-client-secret"
$env:FASTMCP_SERVER_AUTH_AWSCOGNITO_DOMAIN="myapp.auth.us-east-1.amazoncognito.com"
```

```bash
# Linux/Mac
export FASTMCP_SERVER_AUTH_AWSCOGNITO_USER_POOL_ID="us-east-1_XXXXXXXXX"
export FASTMCP_SERVER_AUTH_AWSCOGNITO_REGION="us-east-1"
export FASTMCP_SERVER_AUTH_AWSCOGNITO_CLIENT_ID="your-app-client-id"
export FASTMCP_SERVER_AUTH_AWSCOGNITO_CLIENT_SECRET="your-app-client-secret"
export FASTMCP_SERVER_AUTH_AWSCOGNITO_DOMAIN="myapp.auth.us-east-1.amazoncognito.com"
```

### 3. Run the Server

```bash
cd examples/Auth/AwsCognitoOAuth
dotnet run
```

The server will start on `http://localhost:5006` with:
- MCP endpoint: `http://localhost:5006/mcp`
- OAuth callback: `http://localhost:5006/auth/callback`
- OAuth discovery: `http://localhost:5006/.well-known/oauth-authorization-server`

### 4. Test with MCP Client

MCP clients can automatically discover the authentication requirements and initiate the OAuth flow. The OAuth Proxy handles:
- Dynamic Client Registration (DCR)
- Authorization code flow with PKCE
- Token exchange and validation

### 5. Test with REST Client

Open `aws-cognito-oauth-tests.rest` in VS Code with the REST Client extension to test the complete OAuth flow manually.

## Features Demonstrated

- **OAuth Proxy Pattern**: Enables DCR for AWS Cognito
- **Token Verification**: Validates AWS Cognito JWT tokens
- **Protected Tools**: Tools with `[Authorize]` attribute require authentication
- **User Claims**: Access authenticated user information
- **Default Scopes**: Automatically includes `openid`, `profile`, `email`