const jose = require('jose')

// Middleware to extract and verify JWT from cookies
const extractJwtToken = (jwksService) => async (req, res, next) => {
  try {
    // First check for token in cookie
    const token = req.cookies.auth_token

    // Fallback to Authorization header if no cookie
    const authHeader = req.headers.authorization
    const headerToken =
      authHeader && authHeader.startsWith('Bearer ')
        ? authHeader.split(' ')[1]
        : null

    // Use token from cookie or header
    const accessToken = token || headerToken

    if (!accessToken) {
      return res.status(401).json({ error: 'Authentication required' })
    }

    try {
      // Verify the token using JWKS
      const decodedToken = await jwksService.verifyToken(accessToken)

      req.user = {
        id: decodedToken.sub,
        email: decodedToken.email,
        name: decodedToken.name,
        preferred_username: decodedToken.preferred_username,
        source: 'keycloak',
      }

      // If token came from header, set it as a secure cookie
      if (headerToken && !token) {
        // Set HTTP-only cookie that can't be accessed by JavaScript
        res.cookie('auth_token', headerToken, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production', // Only use secure in production
          sameSite: 'strict',
          maxAge: 3600000, // 1 hour
        })
      }

      next()
    } catch (tokenError) {
      return res.status(401).json({ error: 'Authentication failed' })
    }
  } catch (error) {
    console.error('Authentication error:', error)
    res.status(401).json({ error: 'Authentication failed' })
  }
}

module.exports = {
  extractJwtToken,
}
