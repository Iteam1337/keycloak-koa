import axios from 'axios'
import * as jose from 'jose'

import { JwksService } from '../src/lib/jwksService'
import { TokenService } from '../src/lib/tokenService'

describe('TokenService', () => {
  const mockKeycloakUrl = 'https://auth.example.com/realms/test-realm'
  const mockClientId = 'test-client'
  const mockClientSecret = 'test-secret'
  let tokenService: TokenService

  beforeEach(() => {
    tokenService = new TokenService(
      mockKeycloakUrl,
      mockClientId,
      mockClientSecret
    )
    jest.clearAllMocks()
  })

  describe('exchangeCodeForTokens', () => {
    it('should exchange code for tokens successfully', async () => {
      const mockCode = 'test-auth-code'
      const mockRedirectUri = 'http://localhost:3000/callback'
      const mockTokenResponse = {
        access_token: 'mock-access-token',
        refresh_token: 'mock-refresh-token',
        id_token: 'mock-id-token',
        expires_in: 3600,
        token_type: 'Bearer',
      }

      jest.spyOn(axios, 'post').mockResolvedValue({ data: mockTokenResponse })

      const result = await tokenService.exchangeCodeForTokens(
        mockCode,
        mockRedirectUri
      )

      expect(axios.post).toHaveBeenCalledWith(
        `${mockKeycloakUrl}/protocol/openid-connect/token`,
        expect.stringContaining('grant_type=authorization_code'),
        expect.any(Object)
      )

      expect(axios.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining(`client_id=${mockClientId}`),
        expect.any(Object)
      )

      expect(axios.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining(`client_secret=${mockClientSecret}`),
        expect.any(Object)
      )

      expect(axios.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining(`code=${mockCode}`),
        expect.any(Object)
      )

      expect(axios.post).toHaveBeenCalledWith(
        expect.any(String),
        expect.stringContaining(
          `redirect_uri=${encodeURIComponent(mockRedirectUri)}`
        ),
        expect.any(Object)
      )

      expect(result).toEqual(mockTokenResponse)
    })

    it('should throw error if client secret is missing', async () => {
      const tokenServiceNoSecret = new TokenService(
        mockKeycloakUrl,
        mockClientId,
        undefined
      )

      await expect(
        tokenServiceNoSecret.exchangeCodeForTokens('code', 'uri')
      ).rejects.toThrow('Missing client secret configuration')
    })

    it('should handle token exchange errors', async () => {
      jest.spyOn(axios, 'post').mockRejectedValue(new Error('Invalid code'))

      await expect(
        tokenService.exchangeCodeForTokens('invalid-code', 'uri')
      ).rejects.toThrow('Invalid code')
    })
  })

  describe('decodeToken', () => {
    it('should decode a JWT token', () => {
      const mockDecodedToken = { sub: 'user123', email: 'user@example.com' }
      jest.spyOn(jose, 'decodeJwt').mockReturnValue(mockDecodedToken)

      const result = tokenService.decodeToken('mock.jwt.token')

      expect(jose.decodeJwt).toHaveBeenCalledWith('mock.jwt.token')
      expect(result).toEqual(mockDecodedToken)
    })
  })

  describe('extractUserFromToken', () => {
    it('should extract user from verified token', async () => {
      const mockToken = 'mock.jwt.token'
      const mockVerifiedToken = {
        sub: 'user123',
        email: 'user@example.com',
        name: 'Test User',
        preferred_username: 'testuser',
      }

      const mockJwksService = new JwksService(mockKeycloakUrl)
      jest
        .spyOn(mockJwksService, 'verifyToken')
        .mockResolvedValue(mockVerifiedToken)

      const result = await tokenService.extractUserFromToken(
        mockToken,
        mockJwksService
      )

      expect(mockJwksService.verifyToken).toHaveBeenCalledWith(mockToken)
      expect(result).toMatchObject({
        id: 'user123',
        email: 'user@example.com',
        name: 'Test User',
        preferred_username: 'testuser',
      })
    })

    it('should fall back to decoding without verification if no jwksService provided', async () => {
      const mockToken = 'mock.jwt.token'
      const mockDecodedToken = {
        sub: 'user123',
        email: 'user@example.com',
        name: 'Test User',
        preferred_username: 'testuser',
      }

      jest.spyOn(tokenService, 'decodeToken').mockReturnValue(mockDecodedToken)

      const result = await tokenService.extractUserFromToken(mockToken)

      expect(tokenService.decodeToken).toHaveBeenCalledWith(mockToken)
      expect(result).toMatchObject({
        id: 'user123',
        email: 'user@example.com',
        name: 'Test User',
        preferred_username: 'testuser',
      })
    })

    it('should handle token extraction errors', async () => {
      const jwksService = new JwksService(mockKeycloakUrl)
      jest
        .spyOn(jwksService, 'verifyToken')
        .mockRejectedValue(new Error('Token verification failed'))

      await expect(
        tokenService.extractUserFromToken('invalid.token', jwksService)
      ).rejects.toThrow('Token verification failed')
    })
  })

  describe('setCookies', () => {
    it('should set auth cookies correctly', () => {
      const mockRes = {
        cookies: {
          set: jest.fn(),
        },
      }

      const mockTokenData = {
        access_token: 'mock-access-token',
        refresh_token: 'mock-refresh-token',
        expires_in: 3600,
      }

      tokenService.setCookies(mockRes as any, mockTokenData)

      // Check access token cookie
      expect(mockRes.cookies.set).toHaveBeenCalledWith(
        'auth_token',
        'mock-access-token',
        expect.objectContaining({
          httpOnly: true,
          maxAge: 3600 * 1000,
        })
      )

      // Check refresh token cookie
      expect(mockRes.cookies.set).toHaveBeenCalledWith(
        'refresh_token',
        'mock-refresh-token',
        expect.objectContaining({
          httpOnly: true,
          maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        })
      )
    })

    it('should not set refresh token cookie if not provided', () => {
      const mockRes = {
        cookies: {
          set: jest.fn(),
        },
      }

      const mockTokenData = {
        access_token: 'mock-access-token',
        expires_in: 3600,
      }

      tokenService.setCookies(mockRes as any, mockTokenData)

      expect(mockRes.cookies.set).toHaveBeenCalledTimes(1) // Only access_token cookie
      expect(mockRes.cookies.set).toHaveBeenCalledWith(
        'auth_token',
        'mock-access-token',
        expect.any(Object)
      )
    })
  })

  describe('clearAuthCookies', () => {
    it('should clear auth cookies', () => {
      const mockRes = {
        cookies: {
          set: jest.fn(),
        },
      }

      tokenService.clearAuthCookies(mockRes as any)

      expect(mockRes.cookies.set).toHaveBeenCalledWith('auth_token', null, {
        maxAge: 0,
      })
      expect(mockRes.cookies.set).toHaveBeenCalledWith('refresh_token', null, {
        maxAge: 0,
      })
    })
  })
})
