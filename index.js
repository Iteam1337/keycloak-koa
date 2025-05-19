const TokenService = require('./lib/tokenService');
const JwksService = require('./lib/jwksService');
const { extractJwtToken } = require('./lib/middleware');

/**
 * Initialize Keycloak integration for Express/Koa
 * @param {Object} options Configuration options
 * @param {string} options.keycloakUrl Keycloak server URL with realm
 * @param {string} options.clientId Client ID
 * @param {string} options.clientSecret Client secret
 * @returns {Object} Keycloak integration object
 */
function initKeycloak(options) {
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
    }
  };
}

module.exports = initKeycloak;
