const { extractJwtToken } = require('../lib/middleware')

describe('Middleware', () => {
  describe('extractJwtToken', () => {
    let mockReq
    let mockRes
    let mockNext
    let mockJwksService

    beforeEach(() => {
      mockReq = {
        cookies: {},
        headers: {},
      }

      mockRes = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn(),
        cookie: jest.fn(),
      }

      mockNext = jest.fn()

      mockJwksService = {
        verifyToken: jest.fn(),
      }
    })

    it('should extract token from cookie and verify it', async () => {
      // Setup
      mockReq.cookies.auth_token = 'valid-token-from-cookie'

      const mockDecodedToken = {
        sub: 'user123',
        email: 'user@example.com',
        name: 'Test User',
        preferred_username: 'testuser',
      }

      mockJwksService.verifyToken.mockResolvedValue(mockDecodedToken)

      // Execute
      const middleware = extractJwtToken(mockJwksService)
      await middleware(mockReq, mockRes, mockNext)

      // Verify
      expect(mockJwksService.verifyToken).toHaveBeenCalledWith(
        'valid-token-from-cookie'
      )
      expect(mockReq.user).toEqual({
        id: 'user123',
        email: 'user@example.com',
        name: 'Test User',
        preferred_username: 'testuser',
        source: 'keycloak',
      })
      expect(mockNext).toHaveBeenCalled()
    })

    it('should extract token from Authorization header if no cookie', async () => {
      // Setup
      mockReq.headers.authorization = 'Bearer valid-token-from-header'

      const mockDecodedToken = {
        sub: 'user123',
        email: 'user@example.com',
        name: 'Test User',
        preferred_username: 'testuser',
      }

      mockJwksService.verifyToken.mockResolvedValue(mockDecodedToken)

      // Execute
      const middleware = extractJwtToken(mockJwksService)
      await middleware(mockReq, mockRes, mockNext)

      // Verify
      expect(mockJwksService.verifyToken).toHaveBeenCalledWith(
        'valid-token-from-header'
      )
      expect(mockReq.user).toEqual({
        id: 'user123',
        email: 'user@example.com',
        name: 'Test User',
        preferred_username: 'testuser',
        source: 'keycloak',
      })
      expect(mockRes.cookie).toHaveBeenCalledWith(
        'auth_token',
        'valid-token-from-header',
        expect.objectContaining({
          httpOnly: true,
        })
      )
      expect(mockNext).toHaveBeenCalled()
    })

    it('should return 401 if no token is provided', async () => {
      // Execute
      const middleware = extractJwtToken(mockJwksService)
      await middleware(mockReq, mockRes, mockNext)

      // Verify
      expect(mockRes.status).toHaveBeenCalledWith(401)
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Authentication required',
      })
      expect(mockNext).not.toHaveBeenCalled()
    })

    it('should return 401 if token verification fails', async () => {
      // Setup
      mockReq.cookies.auth_token = 'invalid-token'
      mockJwksService.verifyToken.mockRejectedValue(new Error('Invalid token'))

      // Execute
      const middleware = extractJwtToken(mockJwksService)
      await middleware(mockReq, mockRes, mockNext)

      // Verify
      expect(mockRes.status).toHaveBeenCalledWith(401)
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Authentication failed',
      })
      expect(mockNext).not.toHaveBeenCalled()
    })

    it('should handle malformed Authorization header', async () => {
      // Setup with malformed header (missing 'Bearer ' prefix)
      mockReq.headers.authorization = 'invalid-format'

      // Execute
      const middleware = extractJwtToken(mockJwksService)
      await middleware(mockReq, mockRes, mockNext)

      // Verify
      expect(mockRes.status).toHaveBeenCalledWith(401)
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Authentication required',
      })
      expect(mockNext).not.toHaveBeenCalled()
    })

    it('should handle unexpected errors during processing', async () => {
      // Setup
      mockReq.cookies.auth_token = 'valid-token'
      mockJwksService.verifyToken.mockImplementation(() => {
        throw new Error('Unexpected error')
      })

      // Execute
      const middleware = extractJwtToken(mockJwksService)
      await middleware(mockReq, mockRes, mockNext)

      // Verify
      expect(mockRes.status).toHaveBeenCalledWith(401)
      expect(mockRes.json).toHaveBeenCalledWith({
        error: 'Authentication failed',
      })
      expect(mockNext).not.toHaveBeenCalled()
    })
  })
})
