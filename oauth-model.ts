import { db } from "./db";
import type {
  AuthorizationCode,
  Client,  User,
  Token,
  RefreshToken, // Ensure RefreshToken is explicitly imported
  AuthorizationCodeModel,
  ClientCredentialsModel,
  RefreshTokenModel,
  PasswordModel,
  ExtensionModel,
} from "@node-oauth/oauth2-server";
import bcrypt from 'bcryptjs';

// We'll combine all model types for simplicity in this example
type OAuthModel = AuthorizationCodeModel &
  ClientCredentialsModel &
  RefreshTokenModel &
  PasswordModel &
  ExtensionModel;

export class PrismaOAuthModel implements OAuthModel {
  async getClient(clientId: string, clientSecret?: string | null): Promise<Client | undefined> {
    if (process.env.NODE_ENV !== 'production') console.log(`[PrismaOAuthModel] getClient: Called with clientId: '${clientId}', clientSecret: '${clientSecret ? "********" : null}'`);
    if (!clientId) {
      if (process.env.NODE_ENV !== 'production') console.warn('[PrismaOAuthModel] getClient: clientId parameter is missing or empty.');
      return undefined;
    }
    const dbClient = await db.oAuthClient.findUnique({
      where: { clientId },
    });

    if (!dbClient) {
      if (process.env.NODE_ENV !== 'production') console.warn(`[PrismaOAuthModel] getClient: Client not found for clientId: '${clientId}'`);
      return undefined;
    }

    // Client secret validation: Only if a clientSecret is provided in the call.
    // If clientSecret is not provided, we might be in the authorization flow where it's not required yet.
    if (clientSecret) { // A secret was provided by the caller (e.g., token endpoint)
      if (!dbClient.clientSecret) {
        // Request included a secret, but client is registered as public (no secret in DB)
        if (process.env.NODE_ENV !== 'production') console.warn(`[PrismaOAuthModel] getClient: Client secret provided for a public client: '${clientId}'`);
        return undefined; 
      }
      // Both provided secret and DB secret exist, so compare them
      const secretIsValid = bcrypt.compareSync(clientSecret, dbClient.clientSecret);
      if (!secretIsValid) {
        if (process.env.NODE_ENV !== 'production') console.warn(`[PrismaOAuthModel] getClient: Client secret does not match for clientId: '${clientId}'`);
        return undefined;
      }
      if (process.env.NODE_ENV !== 'production') console.log(`[PrismaOAuthModel] getClient: Client secret validated successfully for clientId: '${clientId}'`);
    } else {
      // No clientSecret provided in the call to getClient.
      // This is okay for the authorization part of the flow, or for public clients.
      // If the client IS confidential (has a secret in DB), this means the caller (e.g. authorize endpoint)
      // is not trying to authenticate the client's secret at this stage, just retrieve its details.
      // The token endpoint MUST provide the secret for confidential clients.
      if (process.env.NODE_ENV !== 'production') console.log(`[PrismaOAuthModel] getClient: No clientSecret provided in call for clientId: '${clientId}'. Proceeding without secret validation for this call.`);
    }

    if (process.env.NODE_ENV !== 'production') console.log(`[PrismaOAuthModel] getClient: Successfully found client for clientId '${clientId}'. Returning client.id as '${dbClient.clientId}'.`);

    return {
      id: dbClient.clientId, // This is the actual 'clientId' string from the database
      redirectUris: dbClient.redirectUris,
      grants: dbClient.grants, // e.g., ['authorization_code', 'refresh_token']
      accessTokenLifetime: 3600, // Default to 1 hour in seconds
      refreshTokenLifetime: 1209600, // Default to 2 weeks in seconds
      // If you add these to your Prisma schema for OAuthClient, you can use:
      // accessTokenLifetime: dbClient.accessTokenLifetime || 3600,
      // refreshTokenLifetime: dbClient.refreshTokenLifetime || 1209600,
      // scope: dbClient.scope // If you have a default scope for the client
    };
  }

  async saveToken(token: Token, client: Client, user: User): Promise<Token> {
    if (process.env.NODE_ENV !== 'production') {
      // IMPORTANT: This log contains sensitive token, client, and user information.
      // It is currently conditional and will not run in production.
      // For non-production debugging, ensure this data is handled securely.
      console.log("[OAuthModel] saveToken", { token, client, user });
    }
    const createdToken = await db.oAuthToken.create({
      data: {
        accessToken: token.accessToken,
        accessTokenExpiresAt: token.accessTokenExpiresAt as Date,
        refreshToken: token.refreshToken,
        refreshTokenExpiresAt: token.refreshTokenExpiresAt as Date | undefined,
        scope: Array.isArray(token.scope) ? token.scope.join(' ') : (token.scope as string | undefined),
        client: {
          connect: { clientId: client.id } // client.id is the string OAuth clientId, connecting via the @unique clientId field on OAuthClient
        },
        user: {
          connect: { id: user.id as string } // user.id is the actual user ID (PK) on User
        }
      },
    });

    return {
      ...token,
      // Ensure the returned token matches the Token interface, including any custom properties
      // Prisma returns the created record, which might have more/different fields
      // than what oauth2-server expects for the *return* of saveToken.
      // The important part is that the input `token` object is what gets used by oauth2-server internally.
      // This return is more for confirmation or if you need to pass back the saved entity.
      accessToken: createdToken.accessToken,
      accessTokenExpiresAt: createdToken.accessTokenExpiresAt,
      refreshToken: createdToken.refreshToken ?? undefined,
      refreshTokenExpiresAt: createdToken.refreshTokenExpiresAt ?? undefined,
      scope: createdToken.scope ? createdToken.scope.split(' ') : [],
      client: client, // Add the client to the returned token object
      user: user, // Add the user to the returned token object
    };
  }

  async getAccessToken(accessToken: string): Promise<Token | undefined> {
    if (process.env.NODE_ENV !== 'production') console.log("[OAuthModel] getAccessToken", { accessToken });
    const token = await db.oAuthToken.findUnique({
      where: { accessToken },
      include: { client: true, user: true },
    });

    if (!token) {
      console.error("[OAuthModel] Access token not found");
      return undefined;
    }

    return {
      accessToken: token.accessToken,
      accessTokenExpiresAt: token.accessTokenExpiresAt,
      refreshToken: token.refreshToken ?? undefined,
      refreshTokenExpiresAt: token.refreshTokenExpiresAt ?? undefined,
      scope: token.scope ? token.scope.split(' ') : [],
      client: { 
        id: token.client.clientId, 
        grants: token.client.grants, 
        redirectUris: token.client.redirectUris 
      }, // Map to oauth2-server Client
      user: { id: token.user.id, email: token.user.email, name: token.user.name }, // Map to oauth2-server User
    };
  }

  async verifyScope(token: Token, requiredScope: string | string[]): Promise<boolean> {
    if (process.env.NODE_ENV !== 'production') console.log("[OAuthModel] verifyScope", { tokenScope: token.scope, requiredScope });

    // If no specific scope is required by the caller (e.g., an empty array was passed),
    // then any valid token (which we have, since getAccessToken succeeded) is sufficient.
    const requiredScopesArray = Array.isArray(requiredScope) ? requiredScope : (requiredScope ? [requiredScope] : []);
    if (requiredScopesArray.length === 0) {
      if (process.env.NODE_ENV !== 'production') console.log("[OAuthModel] verifyScope: No specific scopes required by the caller. Returning true.");
      return true;
    }

    // Ensure token.scope is an array for consistent processing
    const tokenScopes = Array.isArray(token.scope) ? token.scope : (token.scope ? [token.scope] : []);

    if (tokenScopes.length === 0) {
      // Token has no scopes, but specific scopes are required.
      if (process.env.NODE_ENV !== 'production') console.warn(`[OAuthModel] verifyScope: Token has no scopes, but [${requiredScopesArray.join(', ')}] were required. Returning false.`);
      return false;
    }

    // Check if all required scopes are present in the token's scopes
    const allScopesMet = requiredScopesArray.every(rs => tokenScopes.includes(rs));
    if (process.env.NODE_ENV !== 'production') console.log(`[OAuthModel] verifyScope: Token scopes [${tokenScopes.join(', ')}] vs Required scopes [${requiredScopesArray.join(', ')}]. All scopes met? ${allScopesMet}`);
    return allScopesMet;
  }

  async getRefreshToken(refreshToken: string): Promise<import('@node-oauth/oauth2-server').RefreshToken | undefined> {
    if (process.env.NODE_ENV !== 'production') console.log("[OAuthModel] getRefreshToken", { refreshToken });
    const token = await db.oAuthToken.findUnique({
      where: { refreshToken },
      include: { client: true, user: true },
    });

    if (!token || !token.refreshToken) { // Ensure refreshToken exists
      console.error("[OAuthModel] Refresh token not found or invalid");
      return undefined;
    }

    // Ensure the returned object matches the RefreshToken interface from @node-oauth/oauth2-server
    // It typically includes: refreshToken, refreshTokenExpiresAt, scope, client, user
    return {
      refreshToken: token.refreshToken, // Must be a string
      refreshTokenExpiresAt: token.refreshTokenExpiresAt ?? undefined,
      scope: token.scope ? token.scope.split(' ') : [],
      client: { 
        id: token.client.clientId, 
        grants: token.client.grants, 
        redirectUris: token.client.redirectUris 
      },
      user: { id: token.user.id, email: token.user.email, name: token.user.name },
    };
  }

  async revokeToken(token: RefreshToken): Promise<boolean> { // Signature changed to RefreshToken
    if (process.env.NODE_ENV !== 'production') console.log("[OAuthModel] revokeToken", { token });

    // The `token` object is what was returned by getAccessToken() or getRefreshToken().
    // It will conform to the RefreshToken interface if it has a `refreshToken` property.
    // The library ensures `token.refreshToken` is present when calling this method as part of RefreshTokenModel.
    
    // RFC 7009: revoking a refresh token should also invalidate associated access tokens.
    // Our current DB structure (one OAuthToken record can have both AT and RT) means
    // deleting the record by refreshToken effectively revokes both.
    const result = await db.oAuthToken.deleteMany({
      where: { refreshToken: token.refreshToken }, // token.refreshToken is guaranteed by RefreshToken type
    });
    if (process.env.NODE_ENV !== 'production') console.log(`[OAuthModel] Attempted to revoke by refreshToken '${token.refreshToken}'. Count: ${result.count}`);
    
    if (result.count > 0) {
        return true;
    }

    // Fallback logic (should ideally not be needed if library is consistent with RefreshTokenModel)
    // This handles cases where the primary revocation by refreshToken might have failed, 
    // but an accessToken is present on the passed token object.
    if (token.accessToken && result.count === 0) {
        const accessResult = await db.oAuthToken.deleteMany({
            where: { accessToken: token.accessToken }
        });
        if (process.env.NODE_ENV !== 'production') console.log(`[OAuthModel] Fallback: Attempted to revoke by accessToken '${token.accessToken}'. Count: ${accessResult.count}`);
        return accessResult.count > 0;
    }
    
    if (process.env.NODE_ENV !== 'production') console.warn(`[OAuthModel] revokeToken: refreshToken '${token.refreshToken}' not found or no token revoked.`);
    return false;
  }

  async saveAuthorizationCode(code: AuthorizationCode, client: Client, user: User): Promise<AuthorizationCode> {
    if (process.env.NODE_ENV !== 'production') console.log(`[PrismaOAuthModel] saveAuthorizationCode: Attempting to save code.`);
    if (process.env.NODE_ENV !== 'production') console.log(`[PrismaOAuthModel] saveAuthorizationCode: Received client.id: '${client.id}' (this will be used for connecting to OAuthClient)`);
    if (process.env.NODE_ENV !== 'production') console.log(`[PrismaOAuthModel] saveAuthorizationCode: Received user.id: '${user.id}'`);
    if (process.env.NODE_ENV !== 'production') console.log(`[PrismaOAuthModel] saveAuthorizationCode: Full code object:`, JSON.stringify(code, null, 2));
    if (process.env.NODE_ENV !== 'production') console.log(`[PrismaOAuthModel] saveAuthorizationCode: Full client object:`, JSON.stringify(client, null, 2));
    if (process.env.NODE_ENV !== 'production') console.log(`[PrismaOAuthModel] saveAuthorizationCode: Full user object:`, JSON.stringify(user, null, 2));

    try {
      const createdCode = await db.oAuthAuthorizationCode.create({
        data: {
          authorizationCode: code.authorizationCode,
          expiresAt: code.expiresAt,
          redirectUri: code.redirectUri,
          scope: Array.isArray(code.scope) ? code.scope.join(' ') : (code.scope || ''), // Ensure scope is a string, default to empty if undefined
          client: { connect: { clientId: client.id } }, // client.id must exist in OAuthClient table
          user: { connect: { id: user.id } },
          ...(code.codeChallenge && { codeChallenge: code.codeChallenge }),
          ...(code.codeChallengeMethod && { codeChallengeMethod: code.codeChallengeMethod }),
        },
      });
      if (process.env.NODE_ENV !== 'production') console.log(`[PrismaOAuthModel] saveAuthorizationCode: Successfully saved code for client.id: '${client.id}'. Auth code: ${createdCode.authorizationCode}`);
      // Return an object conforming to the AuthorizationCode interface, plus any extras if your setup uses them.
      // The library primarily cares that the returned object fulfills the AuthorizationCode contract.
      return {
        authorizationCode: createdCode.authorizationCode,
        expiresAt: createdCode.expiresAt,
        redirectUri: createdCode.redirectUri,
        scope: createdCode.scope ? createdCode.scope.split(' ') : [],
        client: client, // The client object that was passed in
        user: user, // The user object that was passed in
        ...(createdCode.codeChallenge && { codeChallenge: createdCode.codeChallenge }),
        ...(createdCode.codeChallengeMethod && { codeChallengeMethod: createdCode.codeChallengeMethod }),
      };
    } catch (dbError: any) {
      console.error(`[PrismaOAuthModel] saveAuthorizationCode: Database error while saving code for client.id '${client.id}':`, dbError);
      // Log additional details if it's a Prisma known error
      if (dbError.code) console.error(`[PrismaOAuthModel] saveAuthorizationCode: Prisma error code: ${dbError.code}`);
      if (dbError.meta) console.error(`[PrismaOAuthModel] saveAuthorizationCode: Prisma error meta:`, dbError.meta);
      throw dbError; // Re-throw the error to be caught by the calling oauth.authorize()
    }
  }

  async getAuthorizationCode(authorizationCode: string): Promise<AuthorizationCode | undefined> {
    if (process.env.NODE_ENV !== 'production') console.log("[OAuthModel] getAuthorizationCode", { authorizationCode });
    const code = await db.oAuthAuthorizationCode.findUnique({
      where: { authorizationCode },
      include: { client: true, user: true },
    });

    if (!code) {
      console.error("[OAuthModel] Authorization code not found");
      return undefined;
    }

    return {
      authorizationCode: code.authorizationCode,
      expiresAt: code.expiresAt,
      redirectUri: code.redirectUri,
      scope: code.scope ? code.scope.split(' ') : [],
      client: { 
        id: code.client.clientId, 
        grants: code.client.grants, 
        redirectUris: code.client.redirectUris 
      }, // Map to oauth2-server Client
      user: { id: code.user.id, email: code.user.email, name: code.user.name }, // Map to oauth2-server User
      codeChallenge: code.codeChallenge ?? undefined,
      codeChallengeMethod: code.codeChallengeMethod ?? undefined,
    };
  }

  async revokeAuthorizationCode(code: AuthorizationCode): Promise<boolean> {
    if (process.env.NODE_ENV !== 'production') console.log("[OAuthModel] revokeAuthorizationCode", { code });
    try {
      await db.oAuthAuthorizationCode.delete({
        where: { authorizationCode: code.authorizationCode },
      });
      return true;
    } catch (error) {
      console.error("[OAuthModel] Error revoking authorization code:", error);
      return false;
    }
  }
  
  // --- Methods for other grant types or to satisfy comprehensive model interfaces ---

  async getUserFromClient(client: Client): Promise<User | undefined> {
    // Implement if using Client Credentials grant type and associating clients with a user
    if (process.env.NODE_ENV !== 'production') console.warn("[OAuthModel] getUserFromClient - NOT IMPLEMENTED", { client });
    // Example: Fetch the user associated with this client_id if applicable
    // const oauthClient = await db.oAuthClient.findUnique({
    //   where: { clientId: client.id },
    //   include: { user: true },
    // });
    // if (!oauthClient || !oauthClient.user) return undefined;
    // return { id: oauthClient.user.id, /* ... other user props */ };
    return undefined; // Or throw new Error('Client credentials grant not supported');
  }

  async getUser(username: string, password_deprecated: string): Promise<User | undefined> {
    // Implement if using Password grant type (generally not recommended)
    if (process.env.NODE_ENV !== 'production') console.warn("[OAuthModel] getUser - NOT IMPLEMENTED", { username });
    // const user = await db.user.findUnique({ where: { email: username } });
    // if (!user) return undefined;
    // // Verify password here (e.g., using bcrypt.compare)
    // // if (passwordIsValid) return { id: user.id, /* ... */ };
    return undefined; // Or throw new Error('Password grant not supported');
  }

  // --- Optional methods for other grant types or features ---

  // async getUser(username: string, password_ deprecated_never_use: string): Promise<User | undefined> {
  //   // Implement if using Password grant type (generally not recommended for new applications)
  //   if (process.env.NODE_ENV !== 'production') console.log("[OAuthModel] getUser", { username });
  //   const user = await db.user.findUnique({ where: { email: username } });
  //   if (!user) return undefined;
  //   // Add password verification logic here if you store passwords directly (e.g., bcrypt.compare)
  //   // For this example, we assume password check is handled elsewhere or not used.
  //   return { id: user.id, email: user.email, name: user.name }; 
  // }

  // async getUserFromClient(client: Client): Promise<User | undefined> {
  //   // Implement if using Client Credentials grant type and associating clients with a user
  //   if (process.env.NODE_ENV !== 'production') console.log("[OAuthModel] getUserFromClient", { client });
  //   const oauthClient = await db.oAuthClient.findUnique({
  //     where: { clientId: client.id },
  //     include: { user: true },
  //   });
  //   if (!oauthClient || !oauthClient.user) return undefined;
  //   return { id: oauthClient.user.id, email: oauthClient.user.email, name: oauthClient.user.name };
  // }

  // async saveClient(clientData: Partial<Client>): Promise<Client | undefined> {
  //   // For client registration, if you implement it
  //   // This is a simplified example. You'd need more robust logic for client registration.
  //   if (process.env.NODE_ENV !== 'production') console.log("[OAuthModel] saveClient", { clientData });
  //   if (!clientData.id || !clientData.grants || !clientData.redirectUris) {
  //       console.error("[OAuthModel] Insufficient data to save client");
  //       return undefined;
  //   }
  //   const newClient = await db.oAuthClient.create({
  //       data: {
  //           clientId: clientData.id,
  //           clientSecret: clientData.clientSecret || 'some-default-secret', // Handle secret generation
  //           name: clientData.name || 'Unnamed Client',
  //           redirectUris: clientData.redirectUris,
  //           grants: clientData.grants,
  //           // Assuming a default user or logic to assign a user
  //           userId: 'default-user-id', // Replace with actual user ID logic
  //       }
  //   });
  //   return {
  //       id: newClient.clientId,
  //       redirectUris: newClient.redirectUris,
  //       grants: newClient.grants,
  //       clientSecret: newClient.clientSecret,
  //   };
  // }

  // async verifyScope(token: Token, scope: string | string[]): Promise<boolean> {
  //   // Optional: Implement custom scope validation logic
  //   if (process.env.NODE_ENV !== 'production') console.log("[OAuthModel] verifyScope", { token, scope });
  //   if (!token.scope) {
  //     return false;
  //   }
  //   const tokenScopes = Array.isArray(token.scope) ? token.scope : token.scope.split(' ');
  //   const requiredScopes = Array.isArray(scope) ? scope : scope.split(' ');
  //   return requiredScopes.every(s => tokenScopes.includes(s));
  // }

  // generateAccessToken(client: Client, user: User, scope: string | string[]): Promise<string> {
  //   // Optional: Custom access token generation. oauth2-server generates one by default.
  //   if (process.env.NODE_ENV !== 'production') console.log("[OAuthModel] generateAccessToken", { client, user, scope });
  //   // Example: return crypto.randomBytes(32).toString('hex');
  //   throw new Error("Method not implemented (using default).");
  // }

  // generateRefreshToken(client: Client, user: User, scope: string | string[]): Promise<string> {
  //   // Optional: Custom refresh token generation. oauth2-server generates one by default if grant allows.
  //   if (process.env.NODE_ENV !== 'production') console.log("[OAuthModel] generateRefreshToken", { client, user, scope });
  //   // Example: return crypto.randomBytes(32).toString('hex');
  //   throw new Error("Method not implemented (using default).");
  // }

  // generateAuthorizationCode(client: Client, user: User, scope: string | string[]): Promise<string> {
  //   // Optional: Custom authorization code generation. oauth2-server generates one by default.
  //   if (process.env.NODE_ENV !== 'production') console.log("[OAuthModel] generateAuthorizationCode", { client, user, scope });
  //   // Example: return crypto.randomBytes(16).toString('hex');
  //   throw new Error("Method not implemented (using default).");
  // }
}
