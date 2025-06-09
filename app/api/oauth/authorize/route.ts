import { NextRequest, NextResponse } from 'next/server';
import { oauth, Request as OAuthRequest, Response as OAuthResponse } from '@/lib/oauth-server';
import { auth } from '@/auth'; // Your NextAuth.js auth config
import { db } from '@/db';

// Handles the initial GET request to the authorization endpoint (RFC 6749, Section 3.1).
// Its primary role is to authenticate the user and display a consent screen.
// For production, replace the basic HTML form with a robust, user-friendly consent page.
export async function GET(request: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) {
    // User authentication is required. If not authenticated, redirect to the sign-in page.
    // The 'callbackUrl' ensures the user returns to this authorization flow after successful login.
    const loginUrl = new URL('/api/auth/signin', request.url);
    loginUrl.searchParams.set('callbackUrl', request.url);
    return NextResponse.redirect(loginUrl);
  }

  const { searchParams } = new URL(request.url);
  const clientId = searchParams.get('client_id');
  const redirectUri = searchParams.get('redirect_uri');
  const responseType = searchParams.get('response_type');
  const scope = searchParams.get('scope');
  const stateFromClient = searchParams.get('state'); // Client-provided state parameter for CSRF protection and context.
  const codeChallenge = searchParams.get('code_challenge'); // PKCE code challenge.
  const codeChallengeMethod = searchParams.get('code_challenge_method'); // PKCE code challenge method (e.g., 'S256', 'plain').

  if (!clientId || !redirectUri || responseType !== 'code') {
    return NextResponse.json({ error: 'invalid_request', error_description: 'Missing or invalid client_id, redirect_uri, or response_type.' }, { status: 400 });
  }

  try {
    const client = await db.oAuthClient.findUnique({ where: { clientId } });
    if (!client) {
      return NextResponse.json({ error: 'invalid_client', error_description: 'Client not found.' }, { status: 400 });
    }

    // In a production environment, render a dedicated consent page here.
    // This page should clearly display the client's name, requested scopes,
    // and allow the user to explicitly grant or deny access.
    // The example below generates a minimal HTML form for demonstration purposes.
    
    // The form will POST back to this same authorization endpoint URL.
    const formActionUrl = new URL(request.url);

    // Construct the state object to be encoded and passed in the form
    // All relevant OAuth parameters from the GET request are packaged into 'oauthReqInfo'.
    // This object is then base64 encoded and passed as the 'state' in the form submission.
    // This ensures all necessary context is available in the POST handler.
    const oauthReqInfo = {
      response_type: responseType,
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: scope || '',
      state: stateFromClient || '', // Preserves the original client state for CSRF and context continuity.
      code_challenge: codeChallenge || '',
      code_challenge_method: codeChallengeMethod || '',
    };

    // Encode this object to be used as the 'state' value in the form's hidden input
    // This encoded string will be passed through the POST request.
    const formStateValue = Buffer.from(JSON.stringify({ oauthReqInfo })).toString('base64');

    return new NextResponse(`
      <html>
        <body>
          <h1>Authorize ${client.name}</h1>
          <p>The application <strong>${client.name}</strong> wants to access your account.</p>
          <p>Requested scopes: ${scope || 'default'}</p>
          <form method="POST" action="${formActionUrl.pathname}${formActionUrl.search}">
            <input type="hidden" name="user_id" value="${session.user.id}" />
            <input type="hidden" name="client_id" value="${clientId}" />
            <input type="hidden" name="redirect_uri" value="${redirectUri}" />
            <input type="hidden" name="response_type" value="${responseType}" />
            <input type="hidden" name="scope" value="${scope || ''}" />
            <input type="hidden" name="state" value="${formStateValue}" />
            ${codeChallenge ? `<input type="hidden" name="code_challenge" value="${codeChallenge}" />` : ''}
            ${codeChallengeMethod ? `<input type="hidden" name="code_challenge_method" value="${codeChallengeMethod}" />` : ''}
            
            <button type="submit" name="allow" value="true">Allow</button>
            <button type="submit" name="allow" value="false">Deny</button>
          </form>
        </body>
      </html>
    `, { headers: { 'Content-Type': 'text/html' } });

  } catch (error) {
    console.error('[Authorize GET] Error fetching client:', error);
    return NextResponse.json({ error: 'server_error', error_description: 'Could not process authorization request.' }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.json({ error: 'unauthorized', error_description: 'User not authenticated.' }, { status: 401 });
  }

  const formData = await request.formData();
  const allow = formData.get('allow') === 'true';
  const formUserId = formData.get('user_id') as string;
  const encodedStateFromForm = formData.get('state') as string;

  // Security check: Ensure the user ID from the form matches the authenticated session user ID.
  // This prevents potential manipulation of the user context during form submission.
  if (formUserId !== session.user.id) {
    return NextResponse.json({ error: 'invalid_request', error_description: 'User ID mismatch.' }, { status: 400 });
  }

  if (!encodedStateFromForm) {
    return NextResponse.json({ error: 'invalid_request', error_description: 'State parameter missing from form submission.' }, { status: 400 });
  }

  let decodedFormState: any;
  try {
    decodedFormState = JSON.parse(Buffer.from(encodedStateFromForm, 'base64').toString('utf-8'));
  } catch (e) {
    console.error('Failed to decode state from form:', e);
    return NextResponse.json({ error: 'invalid_request', error_description: 'Invalid state parameter format.' }, { status: 400 });
  }

  if (!decodedFormState || typeof decodedFormState.oauthReqInfo !== 'object' || decodedFormState.oauthReqInfo === null) {
    console.error('oauthReqInfo missing or not an object in decoded state from form:', decodedFormState);
    return NextResponse.json({ error: 'invalid_request', error_description: 'Invalid state parameter structure. oauthReqInfo not found.' }, { status: 400 });
  }
  const internalStateObject = decodedFormState.oauthReqInfo;

  const clientId = internalStateObject.client_id as string;
  const redirectUri = internalStateObject.redirect_uri as string;
  const clientStateForCsrf = internalStateObject.state as string; // This is the original state from the client, used for CSRF.
  const codeChallenge = internalStateObject.code_challenge as string;
  const codeChallengeMethod = internalStateObject.code_challenge_method as string;
  const responseType = internalStateObject.response_type as string;
  // const scope = internalStateObject.scope as string; // Scope is available if needed by the OAuth library later.

  if (!allow) {
    if (!redirectUri) {
        return NextResponse.json({ error: 'invalid_request', error_description: 'Missing redirect_uri for denial.' }, { status: 400 });
    }
    const denialUrl = new URL(redirectUri);
    denialUrl.searchParams.set('error', 'access_denied');
    denialUrl.searchParams.set('error_description', 'The user denied the request.');
    if (clientStateForCsrf) denialUrl.searchParams.set('state', clientStateForCsrf);
    return NextResponse.redirect(denialUrl.toString());
  }

  const oauthAuthorizeBody: { [key: string]: any } = {
    client_id: clientId,
    response_type: responseType, // Add response_type here
    // The OAuth library typically infers redirect_uri from client registration or the initial request context.
    // It's not usually part of the body for the `oauth.authorize` call itself.
  };

  if (clientStateForCsrf) {
    oauthAuthorizeBody.state = clientStateForCsrf; // Crucial for CSRF validation
  }
  if (codeChallenge) {
    oauthAuthorizeBody.code_challenge = codeChallenge;
  }
  if (codeChallengeMethod) {
    oauthAuthorizeBody.code_challenge_method = codeChallengeMethod;
  }

  const oauthRequest = new OAuthRequest({
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...Object.fromEntries(request.headers.entries()) },
    method: 'POST', 
    query: {}, // Query parameters from the original GET request are implicitly part of the context for the library.
    body: oauthAuthorizeBody,
  });

  const oauthResponse = new OAuthResponse({});

  try {
    const code = await oauth.authorize(oauthRequest, oauthResponse, {
      authenticateHandler: {
        // Provides the authenticated user context to the OAuth library.
        // The user object should conform to the structure expected by your OAuth model (e.g., containing an 'id' property).
        handle: async () => {
          // Non-null assertions used here assume 'session.user' and its properties are populated
          // due to the authentication check at the beginning of the POST handler.
          return { id: session.user!.id, email: session.user!.email, name: session.user!.name };
        },
      },
      // If the client did not provide a 'state' parameter in the initial request,
      // `allowEmptyState` permits the authorization to proceed. Otherwise, the 'state'
      // from `oauthAuthorizeBody` (which is `clientStateForCsrf`) must match the one stored
      // by the library during the initial phase of the authorization request (if applicable to library internals).
      allowEmptyState: !clientStateForCsrf,
    });

    if (process.env.NODE_ENV !== 'production') {
      console.log('[Authorize POST] Authorization code generated:', code.authorizationCode);
    }

    // The `node-oauth2-server` library should set the redirect location in `oauthResponse.headers.location`.
    if (oauthResponse.status === 302 && oauthResponse.headers?.location) {
      return NextResponse.redirect(oauthResponse.headers.location as string, oauthResponse.status);
    } else {
      // Fallback: If the library doesn't provide a full redirect URL in headers (uncommon for success),
      // construct it manually using the validated redirectUri and the generated authorization code.
      // This ensures the client is redirected correctly even in less typical library responses.
      if (process.env.NODE_ENV !== 'production') {
        console.warn('[Authorize POST] Authorization successful but no explicit redirect URL in OAuthResponse. Constructing manually.');
      }
      const successRedirectUri = new URL(redirectUri);
      successRedirectUri.searchParams.set('code', code.authorizationCode);
      if (clientStateForCsrf) successRedirectUri.searchParams.set('state', clientStateForCsrf);
      return NextResponse.redirect(successRedirectUri.toString());
    }

  } catch (error: any) {
    console.error('[Authorize POST] Error during oauth.authorize:', error);
    const status = error.code || error.status || 500;
    const errBody = { error: error.name || 'server_error', error_description: error.message };

    // For client-side errors (e.g., invalid_request, invalid_client) where a redirect_uri is known
    // and the error is not a server-side issue, redirect back to the client with error parameters.
    // This is per OAuth 2.0 specification (RFC 6749, Section 4.1.2.1).
    if (redirectUri && error.name !== 'server_error' && error.code < 500) {
      try {
        const errorUrl = new URL(redirectUri);
        errorUrl.searchParams.set('error', error.name || 'oauth_error');
        errorUrl.searchParams.set('error_description', error.message);
        if (clientStateForCsrf) errorUrl.searchParams.set('state', clientStateForCsrf);
        return NextResponse.redirect(errorUrl.toString());
      } catch (redirectError) {
        // If constructing the error redirect URL fails, fall back to a JSON error response.
        console.error('[Authorize POST] Error constructing redirect URL for OAuth error:', redirectError);
      }
    }
    // For server errors or if redirecting the error is not possible/appropriate, return a JSON error response.
    return NextResponse.json(errBody, { status });
  }
}
