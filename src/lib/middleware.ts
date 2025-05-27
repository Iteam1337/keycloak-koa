import type { Next as KoaNext, ParameterizedContext as KoaContext } from "koa";
import type {
  NextFunction as ExpressNext,
  Request as ExpressRequest,
  Response as ExpressResponse,
} from "express";
import { JwksService } from "./jwksService";

interface ExpressRequestWithUser extends ExpressRequest {
  user?: {
    id: string;
    email: string;
    name: string;
    preferred_username: string;
    source: string;
  };
}

function isKoaContext(obj: unknown): obj is KoaContext {
  return !!obj && typeof obj === "object" && obj.hasOwnProperty("state");
}

function isExpressRequest(obj: unknown): obj is ExpressRequestWithUser {
  return !!obj && typeof obj === "object" && obj.hasOwnProperty("baseUrl");
}

// Middleware to extract and verify JWT from cookies
export const extractJwtToken =
  (jwksService: JwksService) =>
  async (arg1: unknown, arg2: unknown, arg3?: unknown) => {
    if (isKoaContext(arg1)) {
      return koaMiddleware(jwksService)(arg1, arg2 as KoaNext);
    } else if (isExpressRequest(arg1)) {
      return expressMiddleware(jwksService)(
        arg1,
        arg2 as ExpressResponse,
        arg3 as ExpressNext
      );
    }

    throw new Error("Could not determine middleware type");
  };

const koaMiddleware =
  (jwksService: JwksService) => async (ctx: KoaContext, next: KoaNext) => {
    try {
      // First check for token in cookie
      const token = ctx.cookies.get("auth_token");

      // Fallback to Authorization header if no cookie
      const authHeader = ctx.headers?.authorization;
      const headerToken =
        authHeader && authHeader.startsWith("Bearer ")
          ? authHeader.split(" ")[1]
          : null;

      // Use token from cookie or header
      const accessToken = token || headerToken;

      if (!accessToken) {
        ctx.status = 401;
        ctx.body = { error: "Authentication required" };
        return;
      }

      try {
        // Verify the token using JWKS
        const decodedToken = await jwksService.verifyToken(accessToken);

        // Set user on context/request
        ctx.state.user = {
          id: decodedToken.sub,
          email: decodedToken.email,
          name: decodedToken.name,
          preferred_username: decodedToken.preferred_username,
          source: "keycloak",
        };

        // If token came from header, set it as a secure cookie
        if (headerToken && !token) {
          // Set HTTP-only cookie that can't be accessed by JavaScript
          ctx.cookies.set("auth_token", headerToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict",
            maxAge: 3600000,
          });
        }

        await next();
      } catch (tokenError) {
        ctx.status = 401;
        ctx.body = { error: "Authentication failed" };
      }
    } catch (error) {
      console.error("Authentication error:", error);
      ctx.status = 401;
      ctx.body = { error: "Authentication failed" };
    }
  };

const expressMiddleware =
  (jwksService: JwksService) =>
  async (
    req: ExpressRequestWithUser,
    res: ExpressResponse,
    next: ExpressNext
  ) => {
    try {
      // First check for token in cookie
      const token = req.cookies.auth_token;

      // Fallback to Authorization header if no cookie
      const authHeader = req.headers?.authorization;
      const headerToken =
        authHeader && authHeader.startsWith("Bearer ")
          ? authHeader.split(" ")[1]
          : null;

      // Use token from cookie or header
      const accessToken = token || headerToken;

      if (!accessToken) {
        res.status(401).json({ error: "Authentication required" });
        return;
      }

      try {
        // Verify the token using JWKS
        const decodedToken = await jwksService.verifyToken(accessToken);

        // Set user on context/request
        req.user = {
          id: decodedToken.sub,
          email: decodedToken.email,
          name: decodedToken.name,
          preferred_username: decodedToken.preferred_username,
          source: "keycloak",
        };

        // If token came from header, set it as a secure cookie
        if (headerToken && !token) {
          // Set HTTP-only cookie that can't be accessed by JavaScript
          res.cookie("auth_token", headerToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production", // Only use secure in production
            sameSite: "strict",
            maxAge: 3600000, // 1 hour
          });
        }

        next();
      } catch (tokenError) {
        res.status(401).json({ error: "Authentication failed" });
      }
    } catch (error) {
      console.error("Authentication error:", error);
      res.status(401).json({ error: "Authentication failed" });
    }
  };
