import { NextRequest, NextResponse } from 'next/server';
import { oauth, Request as OAuthRequest, Response as OAuthResponse } from '@/lib/oauth-server';

// CORS Headers for the token endpoint.
// IMPORTANT: For production, 'Access-Control-Allow-Origin' should be restricted to trusted domains.
// Using an environment variable for this is highly recommended.
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': process.env.OAUTH_ALLOWED_ORIGIN || '*', // Consistent with other OAuth endpoints
  'Access-Control-Allow-Methods': 'POST, OPTIONS', // Token endpoint primarily uses POST.
  'Access-Control-Allow-Headers': 'Content-Type, Authorization', // 'Authorization' for client credentials (e.g., client_secret_basic).
};

// Handles CORS preflight requests for the token endpoint.
export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: CORS_HEADERS });
}

// Handles POST requests to the token endpoint (RFC 6749, Section 3.2).
// This endpoint is used to exchange authorization grants (e.g., authorization code, refresh token)
// for access tokens and, optionally, refresh tokens.
export async function POST(request: NextRequest) {
  if (process.env.NODE_ENV !== 'production') {
    console.log('[Token Endpoint] Received request');
  }
  let body: any; // Will hold the parsed request body.
  const contentType = request.headers.get('content-type');
  if (contentType === 'application/x-www-form-urlencoded') {
    const formData = await request.formData();
    body = Object.fromEntries(formData.entries());
  } else if (contentType === 'application/json') {
    // While 'application/x-www-form-urlencoded' is more common for token requests,
    // supporting 'application/json' can be useful for some client implementations or grant types.
    body = await request.json();
  } else {
    // RFC 6749 typically expects 'application/x-www-form-urlencoded'.
    // Reject unsupported content types.
    console.warn(`[Token Endpoint] Unsupported content type: ${contentType}`);
    return NextResponse.json({ error: 'invalid_request', error_description: 'Unsupported Content-Type. Must be application/x-www-form-urlencoded or application/json.' }, { status: 400, headers: CORS_HEADERS });
  }

  const method = request.method.toUpperCase();
  const headers = Object.fromEntries(request.headers.entries());

  // Construct an OAuthRequest object compatible with the node-oauth2-server library.
  const oauthRequest = new OAuthRequest({
    headers: headers, // Pass all original request headers.
    method: method,   // HTTP method (should be POST).
    query: {},        // Query parameters are not typically used by the token endpoint for grant exchange.
    body: body,       // The parsed request body containing grant type and other parameters.
  });

  // Initialize an OAuthResponse object. The `oauth.token()` method will populate this.
  const oauthResponse = new OAuthResponse({});

  try {
    // Call the `oauth.token()` method to process the token request.
    // This method handles grant type validation, client authentication (if applicable),
    // code/refresh token verification, and access token issuance.
    // `oauthResponse` will be populated with the token data or error details.
    const token = await oauth.token(oauthRequest, oauthResponse, {
      // Common options for oauth.token() might include:
      // - requireClientAuthentication: (boolean) an object specifying which grant types require client auth.
      //   e.g. { authorization_code: true, refresh_token: true }
      //   The library's default behavior for client authentication based on grant type is usually sufficient.
      // - accessTokenLifetime: (number) Override default access token lifetime.
      // - refreshTokenLifetime: (number) Override default refresh token lifetime.
    });
    if (process.env.NODE_ENV !== 'production') {
      console.log('[Token Endpoint] Token generation successful.');
      // For deeper debugging, you might log specific non-sensitive fields from the 'token' object here,
      // e.g., console.log('[Token Endpoint] Token expires at:', token.accessTokenExpiresAt);
    }
    // Note: `oauthResponse.body` will be populated by the library with the token response payload.

    // Prepare response headers.
    // Start with CORS headers and any headers already set by the `oauth.token()` method in `oauthResponse.headers`.
    const responseHeadersInit: Record<string, string> = {
        ...CORS_HEADERS,
        ...(oauthResponse.headers || {} as Record<string, string>) // Spread headers from the oauth library's response.
    };
    
    // CRITICAL: Set standard HTTP headers for token responses as per RFC 6749, Section 5.1.
    // These headers prevent caching of sensitive token information.
    // These explicit settings will override any conflicting headers from `oauthResponse.headers`.
    responseHeadersInit['Content-Type'] = 'application/json';
    responseHeadersInit['Cache-Control'] = 'no-store';
    responseHeadersInit['Pragma'] = 'no-cache'; // For compatibility with HTTP/1.0 caches.

    if (process.env.NODE_ENV !== 'production') {
      console.log('[Token Endpoint] Response headers:', responseHeadersInit);
      // The following log is for debugging and shows the token response. It's already guarded by a production check.
      // IMPORTANT: In a production environment, be cautious about logging the full token response body
      // as it contains sensitive access tokens and potentially refresh tokens.
      // This log is behind a NODE_ENV check, but further redaction might be needed if enabled in staging.
      console.log('[Token Endpoint] Response body (for debugging only):', JSON.stringify(oauthResponse.body));
    }

    // Construct the Next.js response.
    // `oauthResponse.body` contains the token data (access_token, token_type, expires_in, refresh_token, scope).
    // `oauthResponse.status` should be 200 for a successful token issuance.
    const nextJsResponse = new NextResponse(JSON.stringify(oauthResponse.body), {
      status: oauthResponse.status || 200, // Default to 200 if status isn't set by the library on success.
      headers: responseHeadersInit,
    });
    
    return nextJsResponse;

  } catch (error: any) {
    // This catch block handles errors thrown by `oauth.token()` or other unexpected errors.
    // The `node-oauth2-server` library typically populates `error.status`, `error.name`, `error.message`,
    // and sometimes `error.headers` for OAuth2-specific errors (e.g., invalid_grant, invalid_client).
    console.error('[Token Endpoint] Error during token processing:', error);
    const status = error.status || error.code || 500; // HTTP status code from the error or default to 500.
    const responseBody = { 
      error: error.name || 'server_error', 
      error_description: error.message || 'An unexpected error occurred.' 
    };
    
    // Prepare headers for the error response.
    // Start with CORS and Content-Type, then merge any headers from the error object.
    const errorResponseHeaders: Record<string, string> = { 
      ...CORS_HEADERS, 
      'Content-Type': 'application/json;charset=UTF-8'
    };
    if (error.headers) {
        Object.entries(error.headers).forEach(([key, value]) => {
            // @ts-ignore TODO: Similar to revoke endpoint, error.headers might have complex value types.
            // Casting to String for now. Proper type handling would be ideal.
            errorResponseHeaders[key.toLowerCase()] = String(value);
        });
    }

    // Construct and return the Next.js error response.
    const nextJsErrorResponse = new NextResponse(JSON.stringify(responseBody), {
        status: status,
        headers: errorResponseHeaders as HeadersInit, // Cast to HeadersInit for NextResponse.
    });

    return nextJsErrorResponse;
  }
}
