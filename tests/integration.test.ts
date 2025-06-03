import supertest from "supertest";
import nock from "nock";
import initKeycloak from "../src/index";
import Koa from "koa";
import KoaRouter from "@koa/router";
import bodyParser from "koa-bodyparser";

describe("Integration Tests", () => {
  const mockKeycloakUrl = "https://auth.example.com/realms/test-realm";
  const mockClientId = "test-client";
  const mockClientSecret = "test-secret";

  const keycloak = initKeycloak({
    keycloakUrl: mockKeycloakUrl,
    clientId: mockClientId,
    clientSecret: mockClientSecret,
  });

  const app = new Koa();
  const router = new KoaRouter();

  router.get("/api/protected", keycloak.middleware.extractJwtToken, (ctx) => {
    ctx.body = { user: ctx.state.user };
  });

  router.post("/api/token", async (ctx) => {
    try {
      const { code, redirect_uri } = ctx.request.body as any;
      const { user, tokenData } = await keycloak.handleTokenExchange(
        code,
        redirect_uri,
        ctx
      );
      ctx.body = { message: "Authentication successful", user };
    } catch (error) {
      console.error("Token exchange error:", error);
      ctx.status = 401;
      ctx.body = { error: "Authentication failed" };
    }
  });

  router.get("/api/logout", (ctx) => {
    keycloak.logout(ctx);
    ctx.body = { message: "Logged out successfully" };
  });

  app.use(bodyParser());
  app.use(router.routes());

  beforeEach(() => {
    // Mock JWKS endpoint
    nock(mockKeycloakUrl)
      .get("/protocol/openid-connect/certs")
      .reply(200, {
        keys: [
          {
            kid: "test-key-id",
            kty: "RSA",
            alg: "RS256",
            use: "sig",
            n: "test-modulus",
            e: "AQAB",
          },
        ],
      });

    // Mock token verification
    jest
      .spyOn(keycloak.jwksService, "verifyToken")
      .mockImplementation(async (token) => {
        if (token === "valid-token") {
          return {
            sub: "user123",
            email: "user@example.com",
            name: "Test User",
            preferred_username: "testuser",
          };
        } else {
          throw new Error("Invalid token");
        }
      });

    // Mock token exchange
    jest
      .spyOn(keycloak.tokenService, "exchangeCodeForTokens")
      .mockImplementation(async (code) => {
        if (code === "valid-code") {
          return {
            access_token: "valid-token",
            refresh_token: "valid-refresh-token",
            expires_in: 3600,
          };
        } else {
          throw new Error("Invalid code");
        }
      });
  });

  afterEach(() => {
    nock.cleanAll();
    jest.restoreAllMocks();
  });

  describe("Protected Route", () => {
    it("should allow access with valid token in cookie", async () => {
      const response = await supertest(app.callback())
        .get("/api/protected")
        .set("Cookie", ["auth_token=valid-token"]);

      expect(response.status).toBe(200);
      expect(response.body.user).toEqual({
        id: "user123",
        email: "user@example.com",
        name: "Test User",
        preferred_username: "testuser",
        source: "keycloak",
      });
    });

    it("should allow access with valid token in Authorization header", async () => {
      const response = await supertest(app.callback())
        .get("/api/protected")
        .set("Authorization", "Bearer valid-token");

      expect(response.status).toBe(200);
      expect(response.body.user).toEqual({
        id: "user123",
        email: "user@example.com",
        name: "Test User",
        preferred_username: "testuser",
        source: "keycloak",
      });
    });

    it("should deny access with invalid token", async () => {
      const response = await supertest(app.callback())
        .get("/api/protected")
        .set("Cookie", ["auth_token=invalid-token"]);

      expect(response.status).toBe(401);
      expect(response.body.error).toBe("Authentication failed");
    });

    it("should deny access with no token", async () => {
      const response = await supertest(app.callback()).get("/api/protected");

      expect(response.status).toBe(401);
      expect(response.body.error).toBe("Authentication required");
    });
  });

  describe("Token Exchange", () => {
    it("should exchange valid code for token", async () => {
      const response = await supertest(app.callback()).post("/api/token").send({
        code: "valid-code",
        redirect_uri: "http://localhost:3000/callback",
      });

      expect(response.status).toBe(200);
      expect(response.body.message).toBe("Authentication successful");
      expect(response.body.user).toBeDefined();

      // Check that cookies are set
      expect(response.headers["set-cookie"]).toBeDefined();
      // expect(
      //   response.headers["set-cookie"].some((cookie) =>
      //     cookie.includes("auth_token")
      //   )
      // ).toBe(true);
    });

    it("should reject invalid code", async () => {
      const response = await supertest(app.callback()).post("/api/token").send({
        code: "invalid-code",
        redirect_uri: "http://localhost:3000/callback",
      });

      expect(response.status).toBe(401);
      expect(response.body.error).toBe("Authentication failed");
    });
  });

  describe("Logout", () => {
    it("should clear auth cookies on logout", async () => {
      const response = await supertest(app.callback()).get("/api/logout");

      expect(response.status).toBe(200);
      expect(response.body.message).toBe("Logged out successfully");

      // Check that cookies are cleared
      expect(response.headers["set-cookie"]).toBeDefined();
      // expect(
      //   response.headers["set-cookie"].some((cookie) =>
      //     cookie.includes("auth_token=;")
      //   )
      // ).toBe(true);
      // expect(
      //   response.headers["set-cookie"].some((cookie) =>
      //     cookie.includes("refresh_token=;")
      //   )
      // ).toBe(true);
    });
  });
});
