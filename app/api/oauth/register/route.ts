import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/db';
import bcrypt from 'bcryptjs';
import { randomBytes } from 'crypto'; // For generating client ID/secret

// CORS Headers for the client registration endpoint.
// IMPORTANT: For production, 'Access-Control-Allow-Origin' should be restricted to trusted domains.
// '*' is used here for example purposes and broader initial usability but is not secure for production.
// Consider protecting this endpoint with an initial registration access token or other authentication mechanism if it's publicly accessible.
const corsHeaders = {
  'Access-Control-Allow-Origin': process.env.OAUTH_ALLOWED_ORIGIN || '*', // Example: Use an environment variable
  'Access-Control-Allow-Methods': 'POST, OPTIONS', // This endpoint primarily uses POST for registration.
  'Access-Control-Allow-Headers': 'Content-Type, Authorization', // 'Authorization' might be used if this endpoint is protected.
};

// Defines the expected shape of the client registration request body.
// This interface is based on RFC 7591 (OAuth 2.0 Dynamic Client Registration Protocol).
// Adapt and extend these fields based on your specific requirements and supported client metadata.
interface ClientRegistrationRequest {
  client_name?: string;
  redirect_uris: string[];
  grant_types?: string[];
  response_types?: string[];
  scope?: string;
  token_endpoint_auth_method?: string; // E.g., 'client_secret_basic', 'client_secret_post', 'none'. Defaults to 'client_secret_post' if not provided.
  // Consider adding other standard RFC 7591 fields like:
  // logo_uri?: string;
  // client_uri?: string; // URL of the home page of the client application.
  // policy_uri?: string; // URL that the Relying Party Client provides to an End-User to read about how the End-User's profile data will be used.
  // tos_uri?: string; // URL that the Relying Party Client provides to an End-User to read about the Relying Party's terms of service.
  // jwks_uri?: string; // URL for the Client's JSON Web Key Set [JWK] document. If the Client signs requests to the Server, it contains the signing key(s) the Server uses to validate signatures from the Client.
  // contacts?: string[]; // Array of strings representing ways to contact people responsible for this client, typically email addresses.
}

// Defines the shape of the client registration response, conforming to RFC 7591.
interface ClientRegistrationResponse {
  client_id: string; // The generated client ID.
  client_secret?: string; // The generated client secret. IMPORTANT: This is returned ONLY upon registration and should be stored securely by the client. Not returned if 'token_endpoint_auth_method' is 'none'.
  client_secret_expires_at: number; // Timestamp (seconds since epoch) when the client_secret expires. 0 indicates that the client_secret never expires.
  client_id_issued_at: number; // Timestamp (seconds since epoch) when the client_id was issued.
  client_name?: string;
  redirect_uris: string[];
  grant_types?: string[];
  response_types?: string[];
  scope?: string;
  token_endpoint_auth_method?: string;
  // As per RFC 7591, you might also include:
  // registration_access_token?: string; // An access token that can be used to manage the client's registration (e.g., update or delete).
  // registration_client_uri?: string; // The URI for the client's configuration endpoint, where the registration_access_token can be used.
}

// Security Configuration
// Allowed values and helper functions for strict validation.
const ALLOWED_GRANT_TYPES = ['authorization_code', 'refresh_token', 'client_credentials'];
const ALLOWED_RESPONSE_TYPES = ['code'];
const ALLOWED_TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post', 'none'];

function isRedirectUriAllowed(uri: string): boolean {
  try {
    const parsed = new URL(uri);
    // Require HTTPS in production (except for localhost to aid local testing)
    if (process.env.NODE_ENV === 'production') {
      if (parsed.protocol !== 'https:') return false;
    } else {
      // In non-production, allow http for localhost only
      if (parsed.protocol === 'http:' && parsed.hostname !== 'localhost') return false;
    }
    // RFC 3986: the URI SHOULD NOT contain fragments for OAuth 2.0 redirect URIs.
    if (parsed.hash && parsed.hash !== '') return false;
    return true;
  } catch {
    return false;
  }
}

// Handles CORS preflight requests for the registration endpoint.
export async function OPTIONS(request: NextRequest) {
  return new NextResponse(null, { status: 204, headers: corsHeaders });
}

// Handles the POST request to register a new OAuth client.
// This implements a basic version of dynamic client registration.
export async function POST(request: NextRequest) {
  if (process.env.NODE_ENV !== 'production') {
    console.log('[Register POST] Received client registration request.');
  }
  try {
    const body = await request.json() as ClientRegistrationRequest;

    // Validate redirect_uris
    if (!body.redirect_uris || !Array.isArray(body.redirect_uris) || body.redirect_uris.length === 0) {
      return NextResponse.json({ error: 'invalid_redirect_uri', error_description: 'redirect_uris is required and must not be empty.' }, { status: 400, headers: corsHeaders });
    }
    // Remove duplicates and apply stringent validation rules
    const uniqueRedirectUris = [...new Set(body.redirect_uris.map(uri => uri.trim()))];
    if (uniqueRedirectUris.length !== body.redirect_uris.length) {
      return NextResponse.json({ error: 'invalid_redirect_uri', error_description: 'redirect_uris contains duplicates.' }, { status: 400, headers: corsHeaders });
    }
    if (uniqueRedirectUris.length > 10) {
      return NextResponse.json({ error: 'invalid_redirect_uri', error_description: 'Too many redirect_uris specified; maximum is 10.' }, { status: 400, headers: corsHeaders });
    }
    for (const uri of uniqueRedirectUris) {
      if (!isRedirectUriAllowed(uri)) {
        return NextResponse.json({ error: 'invalid_redirect_uri', error_description: `Redirect URI not allowed: ${uri}` }, { status: 400, headers: corsHeaders });
      }
    }

    // Validate client_name
    if (!body.client_name || typeof body.client_name !== 'string' || body.client_name.trim() === '') {
        return NextResponse.json({ error: 'invalid_client_metadata', error_description: 'client_name is required and must be a non-empty string.' }, { status: 400, headers: corsHeaders });
    }

    // Validate token_endpoint_auth_method
    const tokenEndpointAuthMethod = body.token_endpoint_auth_method || 'client_secret_post';
    if (!ALLOWED_TOKEN_ENDPOINT_AUTH_METHODS.includes(tokenEndpointAuthMethod)) {
      return NextResponse.json({ error: 'invalid_client_metadata', error_description: `token_endpoint_auth_method must be one of ${ALLOWED_TOKEN_ENDPOINT_AUTH_METHODS.join(', ')}` }, { status: 400, headers: corsHeaders });
    }

    // Validate grant_types
    const requestedGrantTypes = (body.grant_types && body.grant_types.length > 0) ? body.grant_types : ['authorization_code', 'refresh_token'];
    if (!requestedGrantTypes.every(gt => ALLOWED_GRANT_TYPES.includes(gt))) {
      return NextResponse.json({ error: 'invalid_client_metadata', error_description: `One or more grant_types are not supported. Allowed: ${ALLOWED_GRANT_TYPES.join(', ')}` }, { status: 400, headers: corsHeaders });
    }

    // Validate response_types
    const requestedResponseTypes = body.response_types && body.response_types.length > 0 ? body.response_types : ['code'];
    if (!requestedResponseTypes.every(rt => ALLOWED_RESPONSE_TYPES.includes(rt))) {
      return NextResponse.json({ error: 'invalid_client_metadata', error_description: `One or more response_types are not supported. Allowed: ${ALLOWED_RESPONSE_TYPES.join(', ')}` }, { status: 400, headers: corsHeaders });
    }

    // Generate a cryptographically strong client ID and client secret.
    const clientId = randomBytes(16).toString('hex'); // 32 characters.
    const clientSecretRaw = randomBytes(32).toString('hex'); // Raw secret for one-time return
    const hashedClientSecret = await bcrypt.hash(clientSecretRaw, 10); // Hashed secret for storage

    if (process.env.NODE_ENV !== 'production') {
      console.log(`[Register POST] Generated clientId: ${clientId}. Client secret is generated but not logged.`);
    }

    const issuedAt = Math.floor(Date.now() / 1000);

    const newClient = await db.oAuthClient.create({
      data: {
        clientId: clientId,
        clientSecret: hashedClientSecret,
        name: body.client_name.trim(),
        redirectUris: uniqueRedirectUris,
        grants: requestedGrantTypes,
        // Default scopes if not specified. 'openid' is standard for OIDC.
        // Ensure these scopes are supported by your authorization server.
        scope: body.scope || 'openid profile email',
        // Associate the client with a user. In many DCR scenarios, clients might be associated
        // with a specific system user or the user/developer who registered the client.
        // This example uses a 'connectOrCreate' for a default system user.
        // Adapt this logic based on your user management and client ownership model.
        user: {
          connectOrCreate: {
            // This attempts to connect to an existing user with the specified email or create one if not found.
            // Replace 'default-system-user@example.com' with a meaningful identifier or logic
            // to associate clients with appropriate user accounts (e.g., the authenticated developer registering the client).
            where: { email: process.env.OAUTH_DEFAULT_CLIENT_OWNER_EMAIL || "default-system-user@example.com" },
            create: {
              email: process.env.OAUTH_DEFAULT_CLIENT_OWNER_EMAIL || "default-system-user@example.com",
              name: "Default Client Owner", // Name for the default user, if created.
              // TODO: Ensure all mandatory fields for your User model are provided here.
              // If your User model requires a password, and you're creating a system user,
              // generate a strong, random password or handle user creation appropriately.
              // Example: password: await bcrypt.hash(randomBytes(16).toString('hex'), 10),
            },
          },
        },
      },
    });

    // Construct the registration response.
    const response: ClientRegistrationResponse = {
      client_id: newClient.clientId,
      // IMPORTANT: The plain text client_secret is returned here ONCE. The client MUST store it securely.
      // Do not include client_secret if the token_endpoint_auth_method is 'none' or if a secret is not applicable.
      client_secret: (tokenEndpointAuthMethod !== 'none') ? clientSecretRaw : undefined,
      client_secret_expires_at: 0, // 0 indicates the secret does not expire. Set a timestamp for expiration if needed.
      client_id_issued_at: issuedAt,
      client_name: newClient.name,
      redirect_uris: newClient.redirectUris,
      grant_types: newClient.grants,
      response_types: requestedResponseTypes || undefined,
      scope: newClient.scope || undefined, // Return actual scope stored.
      // Reflect the requested or default token_endpoint_auth_method.
      token_endpoint_auth_method: tokenEndpointAuthMethod,
    };

    return NextResponse.json(response, { status: 201, headers: corsHeaders });

  } catch (error: any) {
    console.error('[Register POST] Error during client registration:', error);
    // Handle specific Prisma errors, like unique constraint violations for clientId (though rare with random generation).
    if (error.code === 'P2002' && error.meta?.target?.includes('clientId')) {
        // This case is unlikely with cryptographically random client IDs but handled for robustness.
        return NextResponse.json({ error: 'server_error', error_description: 'Failed to generate a unique client ID. Please try again.' }, { status: 500, headers: corsHeaders });
    }
    // Handle other potential errors, e.g., database connection issues.
    return NextResponse.json({ error: 'server_error', error_description: 'An unexpected error occurred while registering the client.' }, { status: 500, headers: corsHeaders });
  }
}
