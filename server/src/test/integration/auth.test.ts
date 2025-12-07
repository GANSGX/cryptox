/**
 * FULL AUTH API INTEGRATION & SECURITY TESTS
 *
 * Covers:
 * - API functionality
 * - OWASP Top 10 vulnerabilities
 * - Security best practices
 * - Edge cases and error handling
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { FastifyInstance } from "fastify";
import { buildApp } from "../helpers/app.helper.js";
import {
  clearDatabase,
  closeDatabase,
  userExists,
  getUser,
} from "../helpers/db.helper.js";
import {
  registerUser,
  loginUser,
  createAuthenticatedUser,
} from "../helpers/user.helper.js";

// Mock public key for tests (64 hex chars = 32 bytes)
const MOCK_PUBLIC_KEY =
  "a1b2c3d4e5f6789012345678901234567890abcdefabcdef1234567890abcdef";

describe("Auth API - Integration & Security Tests", () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildApp();
    await app.ready();
  });

  beforeEach(async () => {
    await clearDatabase();
  });

  afterAll(async () => {
    await app.close();
    await closeDatabase();
  });

  // ============================================================================
  // REGISTRATION TESTS
  // ============================================================================

  describe("POST /api/auth/register - Registration", () => {
    it("should register new user with valid data", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        payload: {
          username: "alice",
          email: "alice@example.com",
          password: "securePassword123",
          public_key: MOCK_PUBLIC_KEY,
          deviceFingerprint: "test-device-alice",
        },
      });

      expect(response.statusCode).toBe(201);

      const body = JSON.parse(response.body);
      expect(body.success).toBe(true);
      expect(body.data.user.username).toBe("alice");
      expect(body.data.user.email).toBe("alice@example.com");
      expect(body.data.token).toBeDefined();
      expect(body.data.user.password).toBeUndefined(); // Password should NOT be returned

      // Verify user exists in database
      const exists = await userExists("alice");
      expect(exists).toBe(true);
    });

    it("should return JWT token with correct structure", async () => {
      const { response, user } = await registerUser(app);

      expect(response.statusCode).toBe(201);
      expect(user.token).toBeDefined();

      // JWT should have 3 parts separated by dots
      const parts = user.token!.split(".");
      expect(parts.length).toBe(3);
    });

    it("should store auth_token in database (not plaintext password)", async () => {
      await registerUser(app, {
        username: "alice",
        password: "myPassword123",
      });

      const user = await getUser("alice");
      // Password field doesn't exist in DB, we store auth_token instead
      expect(user.auth_token).toBeDefined();
      expect(user.auth_token).not.toBe("myPassword123");
      expect(user.salt).toBeDefined(); // Salt should exist
    });

    it("should reject duplicate username with 409", async () => {
      await registerUser(app, { username: "alice" });

      const response = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        payload: {
          username: "alice", // Same username
          email: "alice2@example.com",
          password: "password123",
          public_key: MOCK_PUBLIC_KEY,
          deviceFingerprint: "test-device-2",
        },
      });

      expect(response.statusCode).toBe(409); // Conflict
      const body = JSON.parse(response.body);
      expect(body.success).toBe(false);
      expect(body.error).toContain("already");
    });

    it("should reject duplicate email with 409", async () => {
      await registerUser(app, { email: "alice@example.com" });

      const response = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        payload: {
          username: "bob",
          email: "alice@example.com", // Same email
          password: "password123",
          public_key: MOCK_PUBLIC_KEY,
          deviceFingerprint: "test-device-3",
        },
      });

      expect(response.statusCode).toBe(409);
    });

    it("should reject invalid username format", async () => {
      const invalidUsernames = [
        "ab", // too short (< 3)
        "a".repeat(31), // too long (> 30)
        "Alice", // uppercase not allowed
        "user-name", // hyphens not allowed
        "user name", // spaces not allowed
        "user@name", // special chars not allowed
      ];

      for (const username of invalidUsernames) {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/register",
          payload: {
            username,
            email: `${username}@example.com`,
            password: "password123",
          },
        });

        expect(response.statusCode).toBe(400);
      }
    });

    it("should reject invalid email format", async () => {
      const invalidEmails = [
        "notanemail",
        "missing@domain",
        "@nodomain.com",
        "spaces in@email.com",
      ];

      for (const email of invalidEmails) {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/register",
          payload: {
            username: "alice",
            email,
            password: "password123",
          },
        });

        expect(response.statusCode).toBe(400);
      }
    });

    it("should reject short password (< 8 chars)", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        payload: {
          username: "alice",
          email: "alice@example.com",
          password: "1234567", // Only 7 chars
        },
      });

      expect(response.statusCode).toBe(400);
    });

    it("should reject missing fields", async () => {
      const testCases = [
        { email: "alice@example.com", password: "password123" }, // missing username
        { username: "alice", password: "password123" }, // missing email
        { username: "alice", email: "alice@example.com" }, // missing password
      ];

      for (const payload of testCases) {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/register",
          payload,
        });

        expect(response.statusCode).toBe(400);
      }
    });

    // SECURITY: SQL Injection attempts
    it("should block SQL injection in username", async () => {
      const sqlInjectionPayloads = [
        "admin' OR '1'='1",
        "admin'--",
        "admin' /*",
        "'; DROP TABLE users; --",
        "1' UNION SELECT * FROM users--",
      ];

      for (const malicious of sqlInjectionPayloads) {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/register",
          payload: {
            username: malicious,
            email: "test@example.com",
            password: "password123",
          },
        });

        // Should reject (400 validation or 500 if SQL injection worked)
        expect(response.statusCode).not.toBe(201);
        expect(response.statusCode).not.toBe(200);
      }
    });

    // SECURITY: XSS attempts
    it("should sanitize XSS in username", async () => {
      const xssPayloads = [
        '<script>alert("xss")</script>',
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
      ];

      for (const xss of xssPayloads) {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/register",
          payload: {
            username: xss,
            email: "test@example.com",
            password: "password123",
          },
        });

        // Should be rejected by validation
        expect(response.statusCode).toBe(400);
      }
    });

    // SECURITY: Email normalization
    it("should normalize email to lowercase", async () => {
      await registerUser(app, {
        username: "alice",
        email: "Alice@Example.COM",
      });

      const user = await getUser("alice");
      expect(user.email).toBe("alice@example.com");
    });
  });

  // ============================================================================
  // LOGIN TESTS
  // ============================================================================

  describe("POST /api/auth/login - Login", () => {
    it("should login with correct credentials", async () => {
      const { user } = await registerUser(app, {
        username: "alice",
        password: "testPassword123",
      });

      const { response, token } = await loginUser(
        app,
        "alice",
        "testPassword123",
      );

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.success).toBe(true);
      expect(body.data.token).toBeDefined();
      expect(token).toBeDefined();
    });

    it("should reject wrong password with 401", async () => {
      await registerUser(app, {
        username: "alice",
        password: "correctPassword",
      });

      const { response } = await loginUser(app, "alice", "wrongPassword");

      expect(response.statusCode).toBe(401);
      const body = JSON.parse(response.body);
      expect(body.success).toBe(false);
      expect(body.error).toMatch(/invalid|incorrect|wrong/i);
    });

    it("should reject non-existent user with 401", async () => {
      const { response } = await loginUser(app, "nonexistent", "password123");

      expect(response.statusCode).toBe(401);
    });

    // NOTE: Username is always lowercase (DB constraint: ^[a-z0-9_]+$)
    // So case-sensitivity test is not applicable - uppercase usernames cannot exist

    // SECURITY: Timing attack protection
    it("should take similar time for invalid username and wrong password", async () => {
      await registerUser(app, { username: "alice", password: "correct" });

      // Test invalid username
      const start1 = Date.now();
      await loginUser(app, "nonexistent", "password");
      const time1 = Date.now() - start1;

      // Test wrong password
      const start2 = Date.now();
      await loginUser(app, "alice", "wrong");
      const time2 = Date.now() - start2;

      // Should be within 100ms of each other (timing attack mitigation)
      const timeDiff = Math.abs(time1 - time2);
      expect(timeDiff).toBeLessThan(100);
    });

    // SECURITY: SQL Injection in login
    it("should block SQL injection in login", async () => {
      await registerUser(app, { username: "admin", password: "adminpass" });

      const sqlInjections = ["admin' OR '1'='1", "' OR 1=1--", "admin'--"];

      for (const injection of sqlInjections) {
        const { response } = await loginUser(app, injection, "anything");
        // SQL injection should be rejected by Zod validation (400), not at login stage (401)
        expect(response.statusCode).toBe(400);
      }
    });

    // SECURITY: Missing fields
    it("should reject missing username", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/api/auth/login",
        payload: { password: "password123" },
      });

      expect(response.statusCode).toBe(400);
    });

    it("should reject missing password", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/api/auth/login",
        payload: { username: "alice" },
      });

      expect(response.statusCode).toBe(400);
    });
  });

  // ============================================================================
  // RATE LIMITING TESTS
  // ============================================================================

  describe("Rate Limiting - DoS Protection", () => {
    it("should allow 100 requests per minute (global)", async () => {
      const promises = [];

      // Send 100 requests
      for (let i = 0; i < 100; i++) {
        promises.push(
          app.inject({
            method: "GET",
            url: "/health",
          }),
        );
      }

      const responses = await Promise.all(promises);

      // All should succeed
      responses.forEach((response) => {
        expect(response.statusCode).toBe(200);
      });
    });

    it.skip("should block request 1001 with 429 (Too Many Requests)", async () => {
      // TODO: Run this test separately or move to end (interferes with other tests)
      const promises = [];

      // Send 1001 requests (rate limit is 1000/min)
      for (let i = 0; i < 1001; i++) {
        promises.push(
          app.inject({
            method: "GET",
            url: "/health",
          }),
        );
      }

      const responses = await Promise.all(promises);

      // At least one should be rate limited
      const rateLimited = responses.some((r) => r.statusCode === 429);
      expect(rateLimited).toBe(true);
    });
  });

  // ============================================================================
  // JWT TOKEN TESTS
  // ============================================================================

  describe("JWT Token Security", () => {
    it("should reject invalid JWT format", async () => {
      const response = await app.inject({
        method: "GET",
        url: "/api/me",
        headers: {
          authorization: "Bearer invalid.token.here",
        },
      });

      expect(response.statusCode).toBe(401);
    });

    it("should reject missing Bearer prefix", async () => {
      const user = await createAuthenticatedUser(app);

      const response = await app.inject({
        method: "GET",
        url: "/api/me",
        headers: {
          authorization: user.token!, // Without "Bearer " prefix
        },
      });

      expect(response.statusCode).toBe(401);
    });

    it("should reject tampered JWT token", async () => {
      const user = await createAuthenticatedUser(app);

      // Tamper with token
      const parts = user.token!.split(".");
      parts[2] = "tampered";
      const tamperedToken = parts.join(".");

      const response = await app.inject({
        method: "GET",
        url: "/api/me",
        headers: {
          authorization: `Bearer ${tamperedToken}`,
        },
      });

      expect(response.statusCode).toBe(401);
    });

    it("should reject missing Authorization header", async () => {
      const response = await app.inject({
        method: "GET",
        url: "/api/me",
      });

      expect(response.statusCode).toBe(401);
    });
  });

  // ============================================================================
  // ACCESS CONTROL TESTS (Authorization)
  // ============================================================================

  describe("Access Control - Authorization", () => {
    it("should allow authenticated user to access protected route", async () => {
      const user = await createAuthenticatedUser(app);

      const response = await app.inject({
        method: "GET",
        url: "/api/me",
        headers: {
          authorization: `Bearer ${user.token}`,
        },
      });

      expect(response.statusCode).not.toBe(401);
      expect(response.statusCode).not.toBe(403);
    });

    it("should block unauthenticated user from protected route", async () => {
      const response = await app.inject({
        method: "GET",
        url: "/api/me",
      });

      expect(response.statusCode).toBe(401);
    });
  });

  // ============================================================================
  // ERROR HANDLING & EDGE CASES
  // ============================================================================

  describe("Error Handling & Edge Cases", () => {
    it("should handle malformed JSON payload", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        payload: "this is not json",
        headers: {
          "content-type": "application/json",
        },
      });

      expect(response.statusCode).toBe(400);
    });

    it("should handle empty payload", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        payload: {},
      });

      expect(response.statusCode).toBe(400);
    });

    it("should handle very long username (DoS attempt)", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        payload: {
          username: "a".repeat(10000), // 10KB username
          email: "test@example.com",
          password: "password123",
        },
      });

      expect(response.statusCode).toBe(400);
    });

    it("should handle unicode in username", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        payload: {
          username: "你好世界", // Chinese characters
          email: "test@example.com",
          password: "password123",
        },
      });

      // Should be rejected (only alphanumeric + underscore allowed)
      expect(response.statusCode).toBe(400);
    });

    it("should handle null values", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        payload: {
          username: null,
          email: null,
          password: null,
        },
      });

      expect(response.statusCode).toBe(400);
    });
  });

  // ============================================================================
  // SECURITY HEADERS
  // ============================================================================

  describe("Security Headers", () => {
    it("should include security headers in response", async () => {
      const response = await app.inject({
        method: "GET",
        url: "/health",
      });

      // Check for important security headers
      expect(response.headers["x-content-type-options"]).toBeDefined();
      expect(response.headers["x-frame-options"]).toBeDefined();
      expect(response.headers["x-xss-protection"]).toBeDefined();
    });

    it("should not expose server version", async () => {
      const response = await app.inject({
        method: "GET",
        url: "/health",
      });

      // Server header should not contain version
      const server = response.headers["server"] || "";
      expect(server).not.toMatch(/\d+\.\d+/); // No version numbers
    });

    it("should not expose stack trace in error", async () => {
      const response = await app.inject({
        method: "GET",
        url: "/api/nonexistent-route",
      });

      const body = JSON.parse(response.body);

      // Should NOT contain stack trace
      expect(body.stack).toBeUndefined();
      expect(body.stackTrace).toBeUndefined();
      expect(JSON.stringify(body)).not.toContain("at ");
      expect(JSON.stringify(body)).not.toContain("Error:");
    });
  });
});
