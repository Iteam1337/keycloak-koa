import { JwksService } from './jwksService';

// Middleware to extract and verify JWT from cookies
export const extractJwtToken = (jwksService: JwksService) => async (ctx: any, next: any) => {
  try {
    // For Koa, we need to handle the request and response differently
    const req = ctx.request || ctx;
    const res = ctx.response || ctx;

    // First check for token in cookie
    const token = req.cookies?.auth_token;

    // Fallback to Authorization header if no cookie
    const authHeader = req.headers?.authorization;
    const headerToken =
      authHeader && authHeader.startsWith('Bearer ')
        ? authHeader.split(' ')[1]
        : null;

    // Use token from cookie or header
    const accessToken = token || headerToken;

    if (!accessToken) {
      if (ctx.status) {
        // Koa
        ctx.status = 401;
        ctx.body = { error: 'Authentication required' };
      } else {
        // Express
        res.status(401).json({ error: 'Authentication required' });
      }
      return;
    }

    try {
      // Verify the token using JWKS
      const decodedToken = await jwksService.verifyToken(accessToken);

      // Set user on context/request
      if (ctx.request) {
        // Koa
        ctx.state.user = {
          id: decodedToken.sub,
          email: decodedToken.email,
          name: decodedToken.name,
          preferred_username: decodedToken.preferred_username,
          source: 'keycloak',
        };
      } else {
        // Express
        req.user = {
          id: decodedToken.sub,
          email: decodedToken.email,
          name: decodedToken.name,
          preferred_username: decodedToken.preferred_username,
          source: 'keycloak',
        };
      }

      // If token came from header, set it as a secure cookie
      if (headerToken && !token) {
        // Set HTTP-only cookie that can't be accessed by JavaScript
        if (res.cookie) {
          // Express
          res.cookie('auth_token', headerToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', // Only use secure in production
            sameSite: 'strict',
            maxAge: 3600000, // 1 hour
          });
        } else if (ctx.cookies) {
          // Koa
          ctx.cookies.set('auth_token', headerToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 3600000,
          });
        }
      }

      await next();
    } catch (tokenError) {
      if (ctx.status) {
        // Koa
        ctx.status = 401;
        ctx.body = { error: 'Authentication failed' };
      } else {
        // Express
        res.status(401).json({ error: 'Authentication failed' });
      }
    }
  } catch (error) {
    console.error('Authentication error:', error);
    if (ctx.status) {
      // Koa
      ctx.status = 401;
      ctx.body = { error: 'Authentication failed' };
    } else {
      // Express
      res.status(401).json({ error: 'Authentication failed' });
    }
  }
};
