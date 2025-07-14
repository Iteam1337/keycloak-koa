const jose = require('jose')
const JwksService = require('../lib/jwksService')
const TokenService = require('../lib/tokenService')
const { extractJwtToken } = require('../lib/middleware')

describe('Security Tests', () => {
  const mockKeycloakUrl = 'https://auth.example.com/realms/test-realm'

  describe('Token Tampering Prevention', () => {
    let jwksService
    let tokenService

    beforeEach(() => {
      jwksService = new JwksService(mockKeycloakUrl)
      tokenService = new TokenService(
        mockKeycloakUrl,
        'client-id',
        'client-secret'
      )

      // Mock the JWKS verification
      jwksService.getJwks = jest.fn().mockResolvedValue('mock-jwks')
    })

    it('should reject a token with modified payload', async () => {
      // Create a mock for jose.jwtVerify that simulates signature verification failure
      const jwtVerifySpy = jest.spyOn(jose, 'jwtVerify')
      jwtVerifySpy.mockRejectedValue(new Error('Invalid signature'))

      // Test with a tampered token
      const tamperedToken =
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJoYWNrZXIiLCJlbWFpbCI6ImhhY2tlckBleGFtcGxlLmNvbSJ9.invalid-signature'

      await expect(jwksService.verifyToken(tamperedToken)).rejects.toThrow()

      jwtVerifySpy.mockRestore()
    })

    it('should reject a token with invalid signature', async () => {
      // Create a mock for jose.jwtVerify that simulates signature verification failure
      const jwtVerifySpy = jest.spyOn(jose, 'jwtVerify')
      jwtVerifySpy.mockRejectedValue(new Error('Invalid signature'))

      // Test with an invalid signature
      const invalidSignatureToken =
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIn0.invalid-signature'

      await expect(
        jwksService.verifyToken(invalidSignatureToken)
      ).rejects.toThrow()

      jwtVerifySpy.mockRestore()
    })

    it('should reject a token with expired timestamp', async () => {
      // Create a mock for jose.jwtVerify that simulates expired token
      const jwtVerifySpy = jest.spyOn(jose, 'jwtVerify')
      jwtVerifySpy.mockRejectedValue(new Error('Token expired'))

      // Test with an expired token
      const expiredToken =
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiZXhwIjoxNTE2MjM5MDIyfQ.signature'

      await expect(jwksService.verifyToken(expiredToken)).rejects.toThrow()

      jwtVerifySpy.mockRestore()
    })

    it('should reject a token with wrong issuer', async () => {
      // Create a mock for jose.jwtVerify that simulates wrong issuer
      const jwtVerifySpy = jest.spyOn(jose, 'jwtVerify')
      jwtVerifySpy.mockRejectedValue(new Error('Invalid issuer'))

      // Test with a token from wrong issuer
      const wrongIssuerToken =
        'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaXNzIjoid3JvbmctaXNzdWVyIn0.signature'

      await expect(jwksService.verifyToken(wrongIssuerToken)).rejects.toThrow()

      jwtVerifySpy.mockRestore()
    })
  })

  describe('Cookie Security', () => {
    it('should set secure and httpOnly flags on cookies', () => {
      const tokenService = new TokenService(
        mockKeycloakUrl,
        'client-id',
        'client-secret'
      )
      const mockRes = { cookie: jest.fn() }

      // Set environment to production to test secure flag
      const originalNodeEnv = process.env.NODE_ENV
      process.env.NODE_ENV = 'production'

      tokenService.setCookies(mockRes, {
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        expires_in: 3600,
      })

      // Verify access token cookie
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'auth_token',
        'access-token',
        expect.objectContaining({
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
        })
      )

      // Verify refresh token cookie
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'refresh_token',
        'refresh-token',
        expect.objectContaining({
          httpOnly: true,
          secure: true,
          sameSite: 'strict',
        })
      )

      // Restore environment
      process.env.NODE_ENV = originalNodeEnv
    })
  })

  describe('Middleware Security', () => {
    it('should not expose token details in request object', async () => {
      const mockJwksService = {
        verifyToken: jest.fn().mockResolvedValue({
          sub: 'user123',
          email: 'user@example.com',
          name: 'Test User',
          preferred_username: 'testuser',
          // Sensitive data that should not be exposed
          roles: ['admin'],
          groups: ['sensitive-group'],
          internal_id: 'int-12345',
        }),
      }

      const middleware = extractJwtToken(mockJwksService)

      const mockReq = {
        cookies: { auth_token: 'valid-token' },
        headers: {},
      }

      const mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        cookie: jest.fn(),
      }

      const mockNext = jest.fn()

      await middleware(mockReq, mockRes, mockNext)

      // Verify only allowed fields are exposed
      expect(mockReq.user).toEqual({
        id: 'user123',
        email: 'user@example.com',
        name: 'Test User',
        preferred_username: 'testuser',
        source: 'keycloak',
      })

      // Verify sensitive fields are not exposed
      expect(mockReq.user.roles).toBeUndefined()
      expect(mockReq.user.groups).toBeUndefined()
      expect(mockReq.user.internal_id).toBeUndefined()

      expect(mockNext).toHaveBeenCalled()
    })
  })

  describe('Integration Security Tests', () => {
    it('should handle token verification in the middleware flow', async () => {
      // Setup
      const jwksService = new JwksService(mockKeycloakUrl)
      jwksService.verifyToken = jest.fn().mockResolvedValue({
        sub: 'user123',
        email: 'user@example.com',
        name: 'Test User',
        preferred_username: 'testuser',
      })

      const middleware = extractJwtToken(jwksService)

      const mockReq = {
        cookies: { auth_token: 'valid-token' },
        headers: {},
      }

      const mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        cookie: jest.fn(),
      }

      const mockNext = jest.fn()

      // Execute
      await middleware(mockReq, mockRes, mockNext)

      // Verify
      expect(jwksService.verifyToken).toHaveBeenCalledWith('valid-token')
      expect(mockReq.user).toBeDefined()
      expect(mockNext).toHaveBeenCalled()
    })
  })
})
