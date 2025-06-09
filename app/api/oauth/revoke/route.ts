import { NextRequest, NextResponse } from 'next/server';
import { oauth } from '../../../../lib/oauth-server';
import { Request as OAuthRequest, Response as OAuthResponse } from '@node-oauth/oauth2-server';
import { db } from '../../../../db'; // Import Prisma client
import type { Client } from '@node-oauth/oauth2-server'; // For typing authenticated client

// CORS Headers for the token revocation endpoint.
// IMPORTANT: For production, 'Access-Control-Allow-Origin' should be restricted to trusted domains.
// '*' is used here for example purposes and broader initial usability but is not secure for production.
const corsHeaders = {
  'Access-Control-Allow-Origin': process.env.OAUTH_ALLOWED_ORIGIN || '*', // Example: Use an environment variable
  'Access-Control-Allow-Methods': 'POST, OPTIONS', // RFC 7009 specifies POST.
  'Access-Control-Allow-Headers': 'Content-Type, Authorization', // 'Authorization' for client credentials.
};

// Handles CORS preflight requests for the revocation endpoint.
export async function OPTIONS(request: NextRequest) {
  return new NextResponse(null, { status: 204, headers: corsHeaders });
}

// Handles POST requests to revoke an OAuth 2.0 token, as per RFC 7009.
// This endpoint requires client authentication.
export async function POST(request: NextRequest) {
  // Adapt the NextRequest to the format expected by the node-oauth2-server library.
  const oauthRequest = new OAuthRequest(request);
  // Initialize an OAuthResponse object; the library may populate this, especially on authentication failure.
  const oauthResponse = new OAuthResponse({});

  try {
    // Step 1: Authenticate the client making the revocation request.
    // RFC 7009 requires client authentication for confidential clients.
    // Public clients may also be supported depending on server policy (not typical for revocation).
    // The `oauth.authenticate` method will attempt to authenticate the client using credentials
    // provided in the request (e.g., HTTP Basic Auth with client_id and client_secret).
    const authResult = await oauth.authenticate(oauthRequest, oauthResponse);

    // If `oauth.authenticate` encounters an error (e.g., invalid client credentials),
    // it may directly populate `oauthResponse` with error details.
    if (oauthResponse.status && oauthResponse.status >= 400) {
      let bodyContent = oauthResponse.body;
      if (bodyContent && typeof bodyContent === 'object') bodyContent = JSON.stringify(bodyContent);
      const responseHeaders: Record<string, string> = {};
      if (oauthResponse.headers) {
        for (const [key, value] of Object.entries(oauthResponse.headers)) {
          // @ts-ignore TODO: Addressing this type error (oauthResponse.headers can have values that are string, string[], or number)
          // is important for type safety. For now, casting to String for simplicity in header construction.
          responseHeaders[key.toLowerCase()] = String(value);
        }
      }
      return new NextResponse(bodyContent as BodyInit | null, { 
        status: oauthResponse.status, 
        headers: {...corsHeaders, ...responseHeaders} 
      });
    }

    let client: Client | null = null;
    // `authResult` from `oauth.authenticate` can be a Client object, a Token object, or false.
    // For this revocation endpoint, we expect client credentials authentication, so `authResult` should be a Client object.
    // Authentication via a Bearer token (resulting in a Token object) is not appropriate here.
    if (authResult && typeof authResult === 'object') {
        // Distinguish between a direct Client object and a Token object (which contains a nested client).
        // A Client object typically has 'id' (clientId) and 'grants'.
        // A Token object has 'accessToken', 'client' (a Client object), and 'user'.
        // We need the direct Client object from client credentials authentication.
        if ('id' in authResult && 'grants' in authResult && !('accessToken' in authResult) && !('user' in authResult)) {
            client = authResult as Client;
        }
    }

    // If `client` is still null, it means authentication either failed or returned an unexpected type (e.g., a Token).
    if (!client) {
      console.error("[Revoke Route] Client authentication failed or did not result in a direct Client object. Auth result:", authResult);
      // If `oauth.authenticate` didn't already set an error in `oauthResponse`, set one now.
      if (!(oauthResponse.status && oauthResponse.status >= 400)) {
        oauthResponse.status = 401; // Unauthorized
        oauthResponse.body = { error: 'invalid_client', error_description: 'Client authentication failed or is invalid for this request.' };
        oauthResponse.headers = { ...(oauthResponse.headers || {}), 'Content-Type': 'application/json' };
      }
      
      let bodyContent = oauthResponse.body;
      if (bodyContent && typeof bodyContent === 'object') bodyContent = JSON.stringify(bodyContent);
      const responseHeaders: Record<string, string> = {};
      if (oauthResponse.headers) {
        for (const [key, value] of Object.entries(oauthResponse.headers)) {
          // @ts-ignore TODO: Addressing this type error (oauthResponse.headers can have values that are string, string[], or number)
          // is important for type safety. For now, casting to String for simplicity in header construction.
          responseHeaders[key.toLowerCase()] = String(value);
        }
      }
      return new NextResponse(bodyContent as BodyInit | null, { 
        status: oauthResponse.status || 401, // Default to 401 if not set
        headers: {...corsHeaders, ...responseHeaders} 
      });
    }
    // At this point, `client` is confirmed to be the authenticated Client object.

    // Step 2: Extract the token to be revoked and an optional token_type_hint from the request body.
    // RFC 7009 specifies these parameters are sent as 'application/x-www-form-urlencoded'.
    const formData = await request.formData();
    const tokenToRevoke = formData.get('token') as string;
    const tokenTypeHint = formData.get('token_type_hint') as string | undefined;

    // The 'token' parameter is mandatory.
    if (!tokenToRevoke) {
      return new NextResponse(JSON.stringify({ error: 'invalid_request', error_description: "The 'token' parameter is required." }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    // Step 3: Attempt to revoke the token.
    // It's crucial to ensure that the token being revoked belongs to the authenticated client (`client.id`).
    // This prevents one client from revoking tokens issued to another client.
    let revoked = false;
    if (tokenTypeHint === 'access_token') {
      const result = await db.oAuthToken.deleteMany({
        where: { accessToken: tokenToRevoke, clientId: client.id },
      });
      revoked = result.count > 0;
    } else if (tokenTypeHint === 'refresh_token') {
      const result = await db.oAuthToken.deleteMany({
        where: { refreshToken: tokenToRevoke, clientId: client.id },
      });
      revoked = result.count > 0;
    } else { // If no hint is provided, or if the hint is unrecognized, the server may try to guess.
             // RFC 7009: "If the server is unable to locate the token using the given hint, 
             // it MUST extend its search to all of its supported token types."
             // Common practice: try refresh_token first as they are generally longer-lived and more sensitive.
      let result = await db.oAuthToken.deleteMany({
        where: { refreshToken: tokenToRevoke, clientId: client.id },
      });
      if (result.count > 0) {
        revoked = true;
      } else {
        result = await db.oAuthToken.deleteMany({
          where: { accessToken: tokenToRevoke, clientId: client.id },
        });
        revoked = result.count > 0;
      }
    }

    // RFC 7009, Section 2.2: "The server responds with HTTP status code 200 if the token has been 
    // revoked successfully or if the client submitted an invalid token."
    // This prevents the client from determining if a token was valid by observing the response.
    console.log(`[Revoke Route] Token revocation attempt for client '${client.id}'. Token (first 10 chars): ${tokenToRevoke.substring(0,10)}... Hint: ${tokenTypeHint || 'none'}. DB operation resulted in actual revocation: ${revoked}. Responding HTTP 200.`);
    return new NextResponse(null, { status: 200, headers: corsHeaders });

  } catch (error: any) {
    console.error('[Revoke Route] Unexpected error during token revocation:', error);
    
    // If `oauthResponse` was populated by an error during client authentication (e.g., `oauth.authenticate` failed),
    // use that response, as it's more specific to the authentication failure.
    if (oauthResponse.status && oauthResponse.status >= 400 && oauthResponse.body) {
        let bodyContent = oauthResponse.body;
        if (bodyContent && typeof bodyContent === 'object') bodyContent = JSON.stringify(bodyContent);
        const responseHeaders: Record<string, string> = {};
        if (oauthResponse.headers) {
            for (const [key, value] of Object.entries(oauthResponse.headers)) {
                 // @ts-ignore TODO: Addressing this type error (value could be string[] or number from oauthResponse.headers)
                 // is important for type safety. For now, casting to String.
                responseHeaders[key.toLowerCase()] = String(value);
            }
        }
        return new NextResponse(bodyContent as BodyInit | null, { 
            status: oauthResponse.status, 
            headers: {...corsHeaders, ...responseHeaders}
        });
    }

    // If the error occurred after successful client authentication (e.g., a database issue during revocation)
    // or if `oauthResponse` was not populated by an auth error, construct a generic server error response.
    const errorBody = JSON.stringify({
      error: error.name === 'OAuth2Error' ? (error.error || 'server_error') : 'server_error',
      error_description: error.message || 'An unexpected error occurred during token revocation.',
    });
    return new NextResponse(errorBody, {
      status: error.code || error.status || 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
}
