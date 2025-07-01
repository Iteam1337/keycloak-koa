import nock from "nock";
import * as jose from "jose";

import { JwksService } from "../src/lib/jwksService";

const mockKeycloakUrl = "https://auth.example.com/realms/test-realm";
const mockJwksUri = `${mockKeycloakUrl}/protocol/openid-connect/certs`;

describe("JwksService", () => {
  beforeEach(() => {
    nock.cleanAll();
    jest.restoreAllMocks();
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

      const jwksService = new JwksService(mockKeycloakUrl);
      jwksService.getJwks();
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

      nock(mockKeycloakUrl)
        .get("/protocol/openid-connect/certs")
        .reply(200, mockJwks);

      // Spy on jose.createRemoteJWKSet
      const createRemoteJWKSetSpy = jest.spyOn(jose, "createRemoteJWKSet");

      // First call should fetch
      const jwksService = new JwksService(mockKeycloakUrl);
      await jwksService.getJwks();
      expect(createRemoteJWKSetSpy).toHaveBeenCalledTimes(1);

      // Second call should use cache
      await jwksService.getJwks();
      expect(createRemoteJWKSetSpy).toHaveBeenCalledTimes(1); // Still only called once
    });

    it("should handle JWKS fetch errors", async () => {
      nock(mockKeycloakUrl)
        .get("/protocol/openid-connect/certs")
        .reply(500, { error: "Internal Server Error" });

      const jwksService = new JwksService(mockKeycloakUrl);
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

      const jwksService = new JwksService(mockKeycloakUrl);

      jwksService.getJwks = jest.fn().mockResolvedValueOnce("mock-jwks");

      const jwtVerifySpy = jest.spyOn(jose, "jwtVerify");
      jwtVerifySpy.mockResolvedValueOnce({
        payload: mockPayload,
        protectedHeader: { alg: "RS256" },
      } as any);

      const result = await jwksService.verifyToken("valid.jwt.token");

      expect(result).toEqual(mockPayload);
      expect(jwksService.getJwks).toHaveBeenCalled();
      expect(jwtVerifySpy).toHaveBeenCalledWith(
        "valid.jwt.token",
        "mock-jwks",
        {
          issuer: mockKeycloakUrl,
          audience: "account",
        }
      );
    });

    it("should reject an invalid token", async () => {
      const jwksService = new JwksService(mockKeycloakUrl);
      // Mock the getJwks method
      jwksService.getJwks = jest.fn().mockResolvedValue("mock-jwks");

      // Mock jose.jwtVerify to throw an error
      const jwtVerifySpy = jest.spyOn(jose, "jwtVerify");
      jwtVerifySpy.mockRejectedValue(new Error("Invalid signature"));

      await expect(
        jwksService.verifyToken("invalid.jwt.token")
      ).rejects.toThrow("Invalid signature");
    });

    it("should reject a token with wrong issuer", async () => {
      const jwksService = new JwksService(mockKeycloakUrl);
      // Mock the getJwks method
      jwksService.getJwks = jest.fn().mockResolvedValue("mock-jwks");

      // Mock jose.jwtVerify to throw an error
      const jwtVerifySpy = jest.spyOn(jose, "jwtVerify");
      jwtVerifySpy.mockRejectedValue(new Error("Invalid issuer"));

      await expect(
        jwksService.verifyToken("wrong.issuer.token")
      ).rejects.toThrow("Invalid issuer");
    });
  });
});
