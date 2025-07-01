import nock from "nock";
import jose from "jose";

import { JwksService } from "../src/lib/jwksService";

describe("JwksService", () => {
  const mockKeycloakUrl = "https://auth.example.com/realms/test-realm";
  const mockJwksUri = `${mockKeycloakUrl}/protocol/openid-connect/certs`;
  let jwksService: JwksService;

  beforeEach(() => {
    jwksService = new JwksService(mockKeycloakUrl);

    // Reset nock to ensure clean mocks for each test
    nock.cleanAll();
  });

  describe("getJwks", () => {
    it("should fetch JWKS from Keycloak server", async () => {
      // Mock JWKS response
      const mockJwks = {
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
      };

      nock(mockKeycloakUrl)
        .get("/protocol/openid-connect/certs")
        .reply(200, mockJwks);

      // Spy on jose.createRemoteJWKSet
      const createRemoteJWKSetSpy = jest.spyOn(jose, "createRemoteJWKSet");

      await jwksService.getJwks();
      expect(createRemoteJWKSetSpy).toHaveBeenCalledWith(new URL(mockJwksUri));
      expect(jwksService["lastFetched"]).not.toBeNull();

      createRemoteJWKSetSpy.mockRestore();
    });

    it("should cache JWKS and not fetch again within cache period", async () => {
      // Mock JWKS response
      const mockJwks = {
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
      };

      const jwksScope = nock(mockKeycloakUrl)
        .get("/protocol/openid-connect/certs")
        .reply(200, mockJwks);

      // Spy on jose.createRemoteJWKSet
      const createRemoteJWKSetSpy = jest.spyOn(jose, "createRemoteJWKSet");

      // First call should fetch
      await jwksService.getJwks();
      expect(createRemoteJWKSetSpy).toHaveBeenCalledTimes(1);

      // Second call should use cache
      await jwksService.getJwks();
      expect(createRemoteJWKSetSpy).toHaveBeenCalledTimes(1); // Still only called once

      // Verify the nock endpoint was only called once
      expect(jwksScope.isDone()).toBe(true);

      createRemoteJWKSetSpy.mockRestore();
    });

    it("should handle JWKS fetch errors", async () => {
      nock(mockKeycloakUrl)
        .get("/protocol/openid-connect/certs")
        .reply(500, { error: "Internal Server Error" });

      await expect(jwksService.getJwks()).rejects.toThrow();
    });
  });

  describe("verifyToken", () => {
    it("should verify a valid token", async () => {
      const mockPayload = {
        sub: "user123",
        email: "user@example.com",
        name: "Test User",
        preferred_username: "testuser",
        iss: mockKeycloakUrl,
        aud: "account",
      };

      // Mock the getJwks method
      jwksService.getJwks = jest.fn().mockResolvedValue("mock-jwks");

      // Mock jose.jwtVerify
      const jwtVerifySpy = jest.spyOn(jose, "jwtVerify");

      const result = await jwksService.verifyToken("valid.jwt.token");

      expect(result).toEqual(mockPayload);
      expect(jwtVerifySpy).toHaveBeenCalledWith(
        "valid.jwt.token",
        "mock-jwks",
        {
          issuer: mockKeycloakUrl,
          audience: "account",
        }
      );

      jwtVerifySpy.mockRestore();
    });

    it("should reject an invalid token", async () => {
      // Mock the getJwks method
      jwksService.getJwks = jest.fn().mockResolvedValue("mock-jwks");

      // Mock jose.jwtVerify to throw an error
      const jwtVerifySpy = jest.spyOn(jose, "jwtVerify");
      jwtVerifySpy.mockRejectedValue(new Error("Invalid signature"));

      await expect(
        jwksService.verifyToken("invalid.jwt.token")
      ).rejects.toThrow("Invalid signature");

      jwtVerifySpy.mockRestore();
    });

    it("should reject a token with wrong issuer", async () => {
      // Mock the getJwks method
      jwksService.getJwks = jest.fn().mockResolvedValue("mock-jwks");

      // Mock jose.jwtVerify to throw an error
      const jwtVerifySpy = jest.spyOn(jose, "jwtVerify");
      jwtVerifySpy.mockRejectedValue(new Error("Invalid issuer"));

      await expect(
        jwksService.verifyToken("wrong.issuer.token")
      ).rejects.toThrow("Invalid issuer");

      jwtVerifySpy.mockRestore();
    });
  });
});
