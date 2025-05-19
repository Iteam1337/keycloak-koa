import { TokenService } from './lib/tokenService';
import { JwksService } from './lib/jwksService';
import { extractJwtToken } from './lib/middleware';
import { getAuthUrl, getLogoutUrl, generateRandomState } from './lib/urlHelpers';
import { KeycloakOptions, KeycloakInstance } from './types';

/**
 * Initialize Keycloak integration for Express/Koa
 * @param options Configuration options
 * @returns Keycloak integration object
 */
function initKeycloak(options: KeycloakOptions): KeycloakInstance {
  if (!options) {
    throw new Error('Options are required for Keycloak initialization');
  }

  const { keycloakUrl, clientId, clientSecret } = options;

  if (!keycloakUrl) {
    throw new Error('keycloakUrl is required');
  }

  if (!clientId) {
    throw new Error('clientId is required');
  }

  // Initialize services
  const tokenService = new TokenService(keycloakUrl, clientId, clientSecret);
  const jwksService = new JwksService(keycloakUrl);

  return {
    // Services
    tokenService,
    jwksService,

    // Configuration
    keycloakUrl,
    clientId,

    // Middleware
    middleware: {
      extractJwtToken: extractJwtToken(jwksService),
    },

    // Helper methods
    handleTokenExchange: async (code, redirectUri, res) => {
      const tokenData = await tokenService.exchangeCodeForTokens(code, redirectUri);
      tokenService.setCookies(res, tokenData);
      const user = await tokenService.extractUserFromToken(tokenData.access_token, jwksService);
      return { tokenData, user };
    },

    logout: (res) => {
      tokenService.clearAuthCookies(res);
    },

    // URL helper methods
    getAuthUrl: (redirectUri, options = {}) => getAuthUrl({
      keycloakUrl,
      clientId,
      redirectUri,
      ...options
    }),

    getLogoutUrl: (redirectUri, options = {}) => getLogoutUrl({
      keycloakUrl,
      redirectUri,
      ...options
    }),

    generateRandomState
  };
}

// Export the main function and URL helpers for direct use
export = initKeycloak;
export { getAuthUrl, getLogoutUrl, generateRandomState };
