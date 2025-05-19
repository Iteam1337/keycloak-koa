/**
 * Helper functions to generate Keycloak URLs for various authentication flows
 */

/**
 * Generates a Keycloak authorization URL for the login flow
 * 
 * @param {Object} options Configuration options
 * @param {string} options.keycloakUrl Keycloak server URL with realm
 * @param {string} options.clientId Client ID
 * @param {string} options.redirectUri Redirect URI after successful authentication
 * @param {string} [options.scope='openid'] OAuth scope
 * @param {string} [options.responseType='code'] OAuth response type
 * @param {string} [options.state] Optional state parameter for CSRF protection
 * @param {string} [options.prompt] Optional prompt parameter (none, login, consent)
 * @returns {string} The complete Keycloak authorization URL
 */
function getAuthUrl({
  keycloakUrl,
  clientId,
  redirectUri,
  scope = 'openid',
  responseType = 'code',
  state,
  prompt
}) {
  if (!keycloakUrl) throw new Error('keycloakUrl is required');
  if (!clientId) throw new Error('clientId is required');
  if (!redirectUri) throw new Error('redirectUri is required');

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: responseType,
    scope
  });

  if (state) params.append('state', state);
  if (prompt) params.append('prompt', prompt);

  return `${keycloakUrl}/protocol/openid-connect/auth?${params.toString()}`;
}

/**
 * Generates a Keycloak logout URL
 * 
 * @param {Object} options Configuration options
 * @param {string} options.keycloakUrl Keycloak server URL with realm
 * @param {string} [options.redirectUri] Optional redirect URI after logout
 * @param {string} [options.idTokenHint] Optional ID token hint
 * @returns {string} The complete Keycloak logout URL
 */
function getLogoutUrl({
  keycloakUrl,
  redirectUri,
  idTokenHint
}) {
  if (!keycloakUrl) throw new Error('keycloakUrl is required');

  const params = new URLSearchParams();
  
  if (redirectUri) params.append('redirect_uri', redirectUri);
  if (idTokenHint) params.append('id_token_hint', idTokenHint);

  const queryString = params.toString();
  return `${keycloakUrl}/protocol/openid-connect/logout${queryString ? '?' + queryString : ''}`;
}

/**
 * Generates a random string for use as a state parameter
 * 
 * @param {number} [length=32] Length of the random string
 * @returns {string} Random string
 */
function generateRandomState(length = 32) {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const charactersLength = characters.length;
  
  for (let i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  
  return result;
}

module.exports = {
  getAuthUrl,
  getLogoutUrl,
  generateRandomState
};
