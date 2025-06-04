import type { Next, ParameterizedContext } from "koa";
import { JwksService } from "./jwksService";

// Middleware to extract and verify JWT from cookies
export const extractJwtToken =
  (jwksService: JwksService) =>
  async (ctx: ParameterizedContext, next: Next) => {
    try {
      // First check for token in cookie
      const token = ctx.cookies.get("auth_token");

      // Fallback to Authorization header if no cookie
      const authHeader = ctx.headers.authorization;
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
        console.error("Token verification error:", tokenError);
        ctx.status = 401;
        ctx.body = { error: "Authentication failed" };
      }
    } catch (error) {
      console.error("Authentication error:", error);
      ctx.status = 401;
      ctx.body = { error: "Authentication failed" };
    }
  };
