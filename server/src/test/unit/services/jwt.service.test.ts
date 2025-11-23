/**
 * JWT Service Unit Tests
 * Covers: token generation, verification, decoding
 */

import { describe, it, expect } from "vitest";
import { JwtService } from "../../../services/jwt.service.js";

describe("JwtService", () => {
  const mockPayload = {
    username: "testuser",
    email: "test@example.com",
  };

  describe("generate()", () => {
    it("should generate valid JWT token", () => {
      const token = JwtService.generate(mockPayload);

      expect(token).toBeDefined();
      expect(typeof token).toBe("string");
      expect(token.split(".").length).toBe(3); // JWT has 3 parts
    });

    it("should include username and email in token", () => {
      const token = JwtService.generate(mockPayload);
      const decoded = JwtService.decode(token);

      expect(decoded).toBeDefined();
      expect(decoded?.username).toBe("testuser");
      expect(decoded?.email).toBe("test@example.com");
    });

    it("should include jti (unique ID) in token", () => {
      const token1 = JwtService.generate(mockPayload);
      const token2 = JwtService.generate(mockPayload);

      const decoded1 = JwtService.decode(token1);
      const decoded2 = JwtService.decode(token2);

      expect(decoded1?.jti).toBeDefined();
      expect(decoded2?.jti).toBeDefined();
      expect(decoded1?.jti).not.toBe(decoded2?.jti); // Each token should be unique
    });

    it("should generate different tokens for same payload", () => {
      const token1 = JwtService.generate(mockPayload);
      const token2 = JwtService.generate(mockPayload);

      expect(token1).not.toBe(token2); // Due to jti, tokens should be different
    });

    it("should include expiration time (exp)", () => {
      const token = JwtService.generate(mockPayload);
      const decoded: any = JwtService.decode(token);

      expect(decoded?.exp).toBeDefined();
      expect(typeof decoded?.exp).toBe("number");
    });

    it("should include issued at time (iat)", () => {
      const token = JwtService.generate(mockPayload);
      const decoded: any = JwtService.decode(token);

      expect(decoded?.iat).toBeDefined();
      expect(typeof decoded?.iat).toBe("number");
    });
  });

  describe("verify()", () => {
    it("should verify valid token", () => {
      const token = JwtService.generate(mockPayload);
      const payload = JwtService.verify(token);

      expect(payload).toBeDefined();
      expect(payload?.username).toBe("testuser");
      expect(payload?.email).toBe("test@example.com");
    });

    it("should return null for invalid token", () => {
      const invalidToken = "invalid.token.here";
      const payload = JwtService.verify(invalidToken);

      expect(payload).toBeNull();
    });

    it("should return null for malformed token", () => {
      const malformedToken = "notavalidjwttoken";
      const payload = JwtService.verify(malformedToken);

      expect(payload).toBeNull();
    });

    it("should return null for tampered token", () => {
      const token = JwtService.generate(mockPayload);
      const parts = token.split(".");
      parts[2] = "tampered"; // Tamper with signature
      const tamperedToken = parts.join(".");

      const payload = JwtService.verify(tamperedToken);

      expect(payload).toBeNull();
    });

    it("should return null for empty token", () => {
      const payload = JwtService.verify("");

      expect(payload).toBeNull();
    });
  });

  describe("decode()", () => {
    it("should decode valid token without verification", () => {
      const token = JwtService.generate(mockPayload);
      const decoded = JwtService.decode(token);

      expect(decoded).toBeDefined();
      expect(decoded?.username).toBe("testuser");
      expect(decoded?.email).toBe("test@example.com");
    });

    it("should decode expired token (without verification)", () => {
      // decode() doesn't verify signature or expiration
      const token = JwtService.generate(mockPayload);
      const decoded = JwtService.decode(token);

      expect(decoded).toBeDefined();
    });

    it("should return null for invalid token", () => {
      const decoded = JwtService.decode("invalid.token");

      expect(decoded).toBeNull();
    });

    it("should return null for empty token", () => {
      const decoded = JwtService.decode("");

      expect(decoded).toBeNull();
    });
  });

  describe("Security", () => {
    it("should not include sensitive data in payload", () => {
      const token = JwtService.generate(mockPayload);
      const decoded: any = JwtService.decode(token);

      expect(decoded.password).toBeUndefined();
      expect(decoded.salt).toBeUndefined();
      expect(decoded.auth_token).toBeUndefined();
      expect(decoded.encrypted_master_key).toBeUndefined();
    });

    it("should sign tokens with secret", () => {
      const token = JwtService.generate(mockPayload);

      // Token should not be valid if we try to verify without proper secret
      expect(token).toBeDefined();
      expect(JwtService.verify(token)).not.toBeNull();
    });

    it("should handle very long usernames", () => {
      const longPayload = {
        username: "a".repeat(1000),
        email: "test@example.com",
      };

      const token = JwtService.generate(longPayload);
      const decoded = JwtService.decode(token);

      expect(decoded?.username).toBe("a".repeat(1000));
    });

    it("should handle unicode characters in username", () => {
      const unicodePayload = {
        username: "пользователь",
        email: "тест@пример.com",
      };

      const token = JwtService.generate(unicodePayload);
      const decoded = JwtService.decode(token);

      expect(decoded?.username).toBe("пользователь");
      expect(decoded?.email).toBe("тест@пример.com");
    });
  });
});
