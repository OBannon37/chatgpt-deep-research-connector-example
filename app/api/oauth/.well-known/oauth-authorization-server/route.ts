import { NextRequest, NextResponse } from 'next/server';

// Define CORS headers. For production, 'Access-Control-Allow-Origin' should be restricted
// to specific domains instead of '*' for enhanced security. Consider making this configurable
// via environment variables (e.g., process.env.ALLOWED_ORIGIN).
const corsHeaders = {
  'Access-Control-Allow-Origin': process.env.OAUTH_ALLOWED_ORIGIN || '*', // Example: Use env var or default to '*' for broader example usability
  'Access-Control-Allow-Methods': 'GET, OPTIONS', // Required methods for this endpoint
  'Access-Control-Allow-Headers': 'Content-Type, Authorization', // Common headers
};

// Handles CORS preflight requests.
export async function OPTIONS(request: NextRequest) {
  return NextResponse.json({}, { headers: corsHeaders });
}

// Serves OAuth 2.0 Authorization Server Metadata as defined by RFC 8414.
// This endpoint provides configuration information for OAuth clients.
export async function GET(request: NextRequest) {
  // Dynamically determine the issuer URL based on the request. This ensures the metadata
  // reflects the actual host and protocol, crucial for multi-environment deployments.
  const requestUrl = new URL(request.url);
  const issuer = `${requestUrl.protocol}//${requestUrl.host}`;

  const metadata = {
    issuer: issuer,
    authorization_endpoint: `${issuer}/api/oauth/authorize`,
    token_endpoint: `${issuer}/api/oauth/token`,
    registration_endpoint: `${issuer}/api/oauth/register`,
    revocation_endpoint: `${issuer}/api/oauth/revoke`,
    // jwks_uri: `${issuer}/.well-known/jwks.json`, // Uncomment if using JWT-based access tokens and providing a JWKS endpoint.
    scopes_supported: ["openid", "profile", "email", "offline_access"], // Customize these scopes based on your application's requirements.
    response_types_supported: ["code"], // Indicates support for the Authorization Code grant type.
    response_modes_supported: ["query"], // How authorization responses are returned.
    grant_types_supported: ["authorization_code", "refresh_token"], // Supported grant types for obtaining tokens.
    token_endpoint_auth_methods_supported: ["client_secret_post", "client_secret_basic", "none"],
    // "none" allows public clients (e.g., SPAs, mobile apps that cannot securely store a secret).
    // If only confidential clients are supported, remove "none" for enhanced security.
    // service_documentation: `${issuer}/docs/oauth`, // Optional: Link to your OAuth service documentation.
    // ui_locales_supported: ["en-US", "es-ES"], // Optional: Supported UI locales.
    code_challenge_methods_supported: ["S256", "plain"], // Supported PKCE challenge methods. "S256" is preferred.
  };
  
  return NextResponse.json(metadata, { headers: corsHeaders });
}
