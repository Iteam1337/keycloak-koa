const { getAuthUrl, getLogoutUrl, generateRandomState } = require('../lib/urlHelpers');

describe('URL Helpers', () => {
  const mockKeycloakUrl = 'https://auth.example.com/realms/test-realm';
  const mockClientId = 'test-client';
  const mockRedirectUri = 'https://app.example.com/callback';

  describe('getAuthUrl', () => {
    it('should generate a valid authorization URL with required parameters', () => {
      const url = getAuthUrl({
        keycloakUrl: mockKeycloakUrl,
        clientId: mockClientId,
        redirectUri: mockRedirectUri
      });

      expect(url).toContain(mockKeycloakUrl);
      expect(url).toContain('/protocol/openid-connect/auth');
      expect(url).toContain(`client_id=${mockClientId}`);
      expect(url).toContain(`redirect_uri=${encodeURIComponent(mockRedirectUri)}`);
      expect(url).toContain('response_type=code');
      expect(url).toContain('scope=openid');
    });

    it('should include optional parameters when provided', () => {
      const url = getAuthUrl({
        keycloakUrl: mockKeycloakUrl,
        clientId: mockClientId,
        redirectUri: mockRedirectUri,
        scope: 'openid profile email',
        state: 'test-state',
        prompt: 'login'
      });

      expect(url).toContain('scope=openid%20profile%20email');
      expect(url).toContain('state=test-state');
      expect(url).toContain('prompt=login');
    });

    it('should throw an error when required parameters are missing', () => {
      expect(() => getAuthUrl({
        clientId: mockClientId,
        redirectUri: mockRedirectUri
      })).toThrow('keycloakUrl is required');

      expect(() => getAuthUrl({
        keycloakUrl: mockKeycloakUrl,
        redirectUri: mockRedirectUri
      })).toThrow('clientId is required');

      expect(() => getAuthUrl({
        keycloakUrl: mockKeycloakUrl,
        clientId: mockClientId
      })).toThrow('redirectUri is required');
    });
  });

  describe('getLogoutUrl', () => {
    it('should generate a valid logout URL with only required parameters', () => {
      const url = getLogoutUrl({
        keycloakUrl: mockKeycloakUrl
      });

      expect(url).toContain(mockKeycloakUrl);
      expect(url).toContain('/protocol/openid-connect/logout');
      expect(url).not.toContain('?'); // No query parameters
    });

    it('should include optional parameters when provided', () => {
      const url = getLogoutUrl({
        keycloakUrl: mockKeycloakUrl,
        redirectUri: mockRedirectUri,
        idTokenHint: 'test-id-token'
      });

      expect(url).toContain(`redirect_uri=${encodeURIComponent(mockRedirectUri)}`);
      expect(url).toContain('id_token_hint=test-id-token');
    });

    it('should throw an error when keycloakUrl is missing', () => {
      expect(() => getLogoutUrl({})).toThrow('keycloakUrl is required');
    });
  });

  describe('generateRandomState', () => {
    it('should generate a random string of the default length', () => {
      const state = generateRandomState();
      expect(typeof state).toBe('string');
      expect(state.length).toBe(32);
    });

    it('should generate a random string of the specified length', () => {
      const state = generateRandomState(16);
      expect(state.length).toBe(16);
    });

    it('should generate different strings on each call', () => {
      const state1 = generateRandomState();
      const state2 = generateRandomState();
      expect(state1).not.toEqual(state2);
    });
  });
});
