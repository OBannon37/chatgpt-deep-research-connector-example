import OAuth2Server from '@node-oauth/oauth2-server';
import { PrismaOAuthModel } from '@/oauth-model';

export const oauth = new OAuth2Server({
  model: new PrismaOAuthModel(),
  allowBearerTokensInQueryString: true,
  accessTokenLifetime: 60 * 60, // 1 hour
  refreshTokenLifetime: 60 * 60 * 24 * 14, // 2 weeks
  // You might want to configure other options like:
  // requireClientAuthentication: { authorization_code: false }, // if client secret is not used for auth code grant
});

export const Request = OAuth2Server.Request;
export const Response = OAuth2Server.Response;
