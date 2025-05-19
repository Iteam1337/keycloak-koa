const express = require('express');
const cookieParser = require('cookie-parser');
const supertest = require('supertest');
const nock = require('nock');
const initKeycloak = require('../index');

describe('Integration Tests', () => {
  const mockKeycloakUrl = 'https://auth.example.com/realms/test-realm';
  const mockClientId = 'test-client';
  const mockClientSecret = 'test-secret';
  
  let app;
  let keycloak;
  let request;
  
  beforeEach(() => {
    // Setup Express app
    app = express();
    app.use(express.json());
    app.use(cookieParser());
    
    // Initialize Keycloak
    keycloak = initKeycloak({
      keycloakUrl: mockKeycloakUrl,
      clientId: mockClientId,
      clientSecret: mockClientSecret
    });
    
    // Setup routes
    app.get('/api/protected', keycloak.middleware.extractJwtToken, (req, res) => {
      res.json({ user: req.user });
    });
    
    app.post('/api/token', async (req, res) => {
      try {
        const { code, redirect_uri } = req.body;
        const { user, tokenData } = await keycloak.handleTokenExchange(code, redirect_uri, res);
        res.json({ message: 'Authentication successful', user });
      } catch (error) {
        res.status(401).json({ error: 'Authentication failed' });
      }
    });
    
    app.get('/api/logout', (req, res) => {
      keycloak.logout(res);
      res.json({ message: 'Logged out successfully' });
    });
    
    // Create supertest instance
    request = supertest(app);
    
    // Mock JWKS endpoint
    nock(mockKeycloakUrl)
      .get('/protocol/openid-connect/certs')
      .reply(200, {
        keys: [
          {
            kid: 'test-key-id',
            kty: 'RSA',
            alg: 'RS256',
            use: 'sig',
            n: 'test-modulus',
            e: 'AQAB',
          },
        ],
      });
      
    // Mock token verification
    jest.spyOn(keycloak.jwksService, 'verifyToken').mockImplementation(async (token) => {
      if (token === 'valid-token') {
        return {
          sub: 'user123',
          email: 'user@example.com',
          name: 'Test User',
          preferred_username: 'testuser',
        };
      } else {
        throw new Error('Invalid token');
      }
    });
    
    // Mock token exchange
    jest.spyOn(keycloak.tokenService, 'exchangeCodeForTokens').mockImplementation(async (code) => {
      if (code === 'valid-code') {
        return {
          access_token: 'valid-token',
          refresh_token: 'valid-refresh-token',
          expires_in: 3600,
        };
      } else {
        throw new Error('Invalid code');
      }
    });
  });
  
  afterEach(() => {
    nock.cleanAll();
    jest.restoreAllMocks();
  });
  
  describe('Protected Route', () => {
    it('should allow access with valid token in cookie', async () => {
      const response = await request
        .get('/api/protected')
        .set('Cookie', ['auth_token=valid-token']);
      
      expect(response.status).toBe(200);
      expect(response.body.user).toEqual({
        id: 'user123',
        email: 'user@example.com',
        name: 'Test User',
        preferred_username: 'testuser',
        source: 'keycloak',
      });
    });
    
    it('should allow access with valid token in Authorization header', async () => {
      const response = await request
        .get('/api/protected')
        .set('Authorization', 'Bearer valid-token');
      
      expect(response.status).toBe(200);
      expect(response.body.user).toEqual({
        id: 'user123',
        email: 'user@example.com',
        name: 'Test User',
        preferred_username: 'testuser',
        source: 'keycloak',
      });
    });
    
    it('should deny access with invalid token', async () => {
      const response = await request
        .get('/api/protected')
        .set('Cookie', ['auth_token=invalid-token']);
      
      expect(response.status).toBe(401);
      expect(response.body.error).toBe('Authentication failed');
    });
    
    it('should deny access with no token', async () => {
      const response = await request.get('/api/protected');
      
      expect(response.status).toBe(401);
      expect(response.body.error).toBe('Authentication required');
    });
  });
  
  describe('Token Exchange', () => {
    it('should exchange valid code for token', async () => {
      const response = await request
        .post('/api/token')
        .send({
          code: 'valid-code',
          redirect_uri: 'http://localhost:3000/callback',
        });
      
      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Authentication successful');
      expect(response.body.user).toBeDefined();
      
      // Check that cookies are set
      expect(response.headers['set-cookie']).toBeDefined();
      expect(response.headers['set-cookie'].some(cookie => cookie.includes('auth_token'))).toBe(true);
    });
    
    it('should reject invalid code', async () => {
      const response = await request
        .post('/api/token')
        .send({
          code: 'invalid-code',
          redirect_uri: 'http://localhost:3000/callback',
        });
      
      expect(response.status).toBe(401);
      expect(response.body.error).toBe('Authentication failed');
    });
  });
  
  describe('Logout', () => {
    it('should clear auth cookies on logout', async () => {
      const response = await request.get('/api/logout');
      
      expect(response.status).toBe(200);
      expect(response.body.message).toBe('Logged out successfully');
      
      // Check that cookies are cleared
      expect(response.headers['set-cookie']).toBeDefined();
      expect(response.headers['set-cookie'].some(cookie => cookie.includes('auth_token=;'))).toBe(true);
      expect(response.headers['set-cookie'].some(cookie => cookie.includes('refresh_token=;'))).toBe(true);
    });
  });
});
