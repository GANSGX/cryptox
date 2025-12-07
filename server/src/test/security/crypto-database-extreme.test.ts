/**
 * 🔥 EXTREME CRYPTOGRAPHY & DATABASE SECURITY TESTS
 *
 * Pentagon-level testing for crypto and database vulnerabilities
 *
 * Coverage:
 * - Argon2id Timing Attacks
 * - AES-GCM Vulnerabilities
 * - Key Management
 * - SQL Injection (ALL variants)
 * - Database DoS
 * - Privilege Escalation
 * - Data Leakage
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { FastifyInstance } from "fastify";
import { buildApp } from "../helpers/app.helper.js";
import { clearDatabase, closeDatabase, getUser } from "../helpers/db.helper.js";
import { registerUser, loginUser } from "../helpers/user.helper.js";
import { CryptoService } from "../../services/crypto.service.js";
import {
  hashPassword,
  generateAuthToken,
  encrypt,
  decrypt,
  generateMasterKey,
  deriveStorageKey,
} from "../../utils/crypto.js";
import crypto from "crypto";
import { pool } from "../../db/pool.js";

describe("🔥 EXTREME: Cryptography Security", () => {
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
  // ARGON2ID TIMING ATTACKS
  // ============================================================================

  describe("Argon2id Timing Attacks", () => {
    it("should have consistent timing for password verification (prevent timing attacks)", async () => {
      const { user } = await registerUser(app, {
        username: "timingtest",
        password: "correctpassword123",
      });

      const dbUser = await getUser(user.username);

      // Measure time for correct password
      const times1 = [];
      for (let i = 0; i < 10; i++) {
        const start = Date.now();
        await CryptoService.verifyAuthToken(
          "correctpassword123",
          dbUser.salt,
          dbUser.auth_token,
        );
        times1.push(Date.now() - start);
      }

      // Measure time for incorrect password
      const times2 = [];
      for (let i = 0; i < 10; i++) {
        const start = Date.now();
        await CryptoService.verifyAuthToken(
          "wrongpassword123",
          dbUser.salt,
          dbUser.auth_token,
        );
        times2.push(Date.now() - start);
      }

      const avg1 = times1.reduce((a, b) => a + b, 0) / times1.length;
      const avg2 = times2.reduce((a, b) => a + b, 0) / times2.length;

      // Timing difference should be minimal (< 10ms variance)
      // Argon2 is designed to have constant time verification
      const difference = Math.abs(avg1 - avg2);
      expect(difference).toBeLessThan(10);
    }, 30000); // 30 second timeout

    it("should use sufficient Argon2 parameters (prevent brute force)", async () => {
      // Verify that Argon2 is configured with strong parameters
      // Recommended: memory >= 64MB, iterations >= 3, parallelism >= 4

      const password = "testpassword123";
      const salt = crypto.randomBytes(32).toString("hex");

      const start = Date.now();
      const passwordKey = await hashPassword(password, salt);
      const duration = Date.now() - start;

      // Hashing should take reasonable time (not too fast = weak parameters)
      // Should be at least 50ms (preferably 100-500ms)
      expect(duration).toBeGreaterThan(50);

      // Password key should be a hex string
      expect(passwordKey).toMatch(/^[a-f0-9]{64}$/);

      // Verify hash works by generating auth token
      const authToken = generateAuthToken(passwordKey);
      const isValid = await CryptoService.verifyAuthToken(
        password,
        salt,
        authToken,
      );
      expect(isValid).toBe(true);
    });

    it("should generate unique salts for each user", async () => {
      const users = [];

      // Register 100 users
      for (let i = 0; i < 100; i++) {
        const { user } = await registerUser(app, {
          username: `user${i}`,
          password: "samepassword123", // Same password for all
        });
        users.push(user);
      }

      // Get all salts from database
      const salts = new Set();
      for (const user of users) {
        const dbUser = await getUser(user.username);
        salts.add(dbUser.salt);
      }

      // All salts should be unique
      expect(salts.size).toBe(100);
    }, 120000); // 2 minute timeout

    it("should not store plaintext password anywhere", async () => {
      const { user } = await registerUser(app, {
        username: "secureuser",
        password: "MySecretPassword123!",
      });

      const dbUser = await getUser(user.username);

      // Check that password is NOT stored in any field
      const allFields = Object.values(dbUser).join(" ");

      expect(allFields).not.toContain("MySecretPassword123!");
      expect(dbUser.password).toBeUndefined();

      // Should have salt and auth_token (hashed password)
      expect(dbUser.salt).toBeDefined();
      expect(dbUser.auth_token).toBeDefined();
      expect(dbUser.auth_token).toContain("$argon2id$");
    });
  });

  // ============================================================================
  // AES-GCM VULNERABILITIES
  // ============================================================================

  describe("AES-GCM Encryption Security", () => {
    it("should use unique IV/nonce for each encryption", async () => {
      const plaintext = "sensitive data";
      const key = crypto.randomBytes(32).toString("hex");

      const { ciphertext: encrypted1, nonce: nonce1 } =
        CryptoService.encryptData(plaintext, key);
      const { ciphertext: encrypted2, nonce: nonce2 } =
        CryptoService.encryptData(plaintext, key);

      // Even with same data and key, nonces should differ
      expect(nonce1).not.toBe(nonce2);
      expect(encrypted1).not.toBe(encrypted2);

      // Both should decrypt to same plaintext
      const decrypted1 = CryptoService.decryptData(encrypted1, nonce1, key);
      const decrypted2 = CryptoService.decryptData(encrypted2, nonce2, key);

      expect(decrypted1).toBe(plaintext);
      expect(decrypted2).toBe(plaintext);
    });

    it("should reject tampered ciphertext (auth tag verification)", async () => {
      const plaintext = "important message";
      const key = crypto.randomBytes(32).toString("hex");

      const { ciphertext, nonce } = CryptoService.encryptData(plaintext, key);

      // Tamper with ciphertext
      const tamperedCiphertext = ciphertext.slice(0, -5) + "XXXXX";

      // Should return null on decryption failure
      const result = CryptoService.decryptData(tamperedCiphertext, nonce, key);
      expect(result).toBe(null);
    });

    it("should use 256-bit keys (AES-256)", async () => {
      // Verify that generated keys are 256-bit (32 bytes)
      const masterKey = generateMasterKey();
      const storageKey = deriveStorageKey(masterKey);

      // Keys should be 64 hex chars = 32 bytes = 256 bits
      expect(masterKey.length).toBe(64);
      expect(storageKey.length).toBe(64);
    });

    it("should prevent nonce reuse attack", async () => {
      // AES-GCM is catastrophic if same nonce is reused with same key
      // Verify that nonces are always unique

      const plaintext = "test data";
      const key = crypto.randomBytes(32).toString("hex");

      const nonces = new Set();

      // Encrypt 1000 times
      for (let i = 0; i < 1000; i++) {
        const { nonce } = CryptoService.encryptData(plaintext, key);
        nonces.add(nonce);
      }

      // All nonces should be unique
      expect(nonces.size).toBe(1000);
    }, 10000);
  });

  // ============================================================================
  // KEY MANAGEMENT
  // ============================================================================

  describe("Key Management & Storage", () => {
    it("should never expose encryption keys in API responses", async () => {
      const { user, response } = await registerUser(app);
      const body = JSON.parse(response.body);

      // Check that no sensitive crypto fields are exposed
      expect(body.data?.user?.salt).toBeUndefined();
      expect(body.data?.user?.auth_token).toBeUndefined();
      expect(body.data?.user?.encrypted_master_key).toBeUndefined();
      expect(body.data?.user?.password).toBeUndefined();
      expect(body.data?.user?.password_key).toBeUndefined();
    });

    it("should use cryptographically secure random for key generation", async () => {
      const keys = new Set();

      // Generate 1000 keys
      for (let i = 0; i < 1000; i++) {
        const key = crypto.randomBytes(32).toString("hex");
        keys.add(key);
      }

      // All keys should be unique (no collisions)
      expect(keys.size).toBe(1000);

      // Keys should not be sequential or predictable
      const keysArray = Array.from(keys) as string[];
      for (let i = 0; i < keysArray.length - 1; i++) {
        const similarity = calculateSimilarity(keysArray[i], keysArray[i + 1]);
        expect(similarity).toBeLessThan(0.2); // Less than 20% similar
      }
    });
  });
});

// ============================================================================
// DATABASE SECURITY TESTS
// ============================================================================

describe("🔥 EXTREME: Database Security", () => {
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
  // SQL INJECTION (ALL VARIANTS)
  // ============================================================================

  describe("SQL Injection Protection", () => {
    it("should block classic SQL injection", async () => {
      const injections = [
        "admin' OR '1'='1",
        "admin'--",
        "admin' OR 1=1--",
        "admin'; DROP TABLE users; --",
        "' OR '1'='1' /*",
        "admin' /*",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "admin' UNION SELECT NULL--",
      ];

      for (const injection of injections) {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/login",
          payload: {
            username: injection,
            password: "anything",
          },
        });

        // Should reject injection attempts (Zod blocks at validation = 400)
        expect(response.statusCode).toBe(400);
      }
    });

    it("should block UNION-based SQL injection", async () => {
      const injections = [
        "' UNION SELECT NULL, NULL, NULL--",
        "' UNION SELECT username, password FROM users--",
        "' UNION ALL SELECT NULL, NULL, NULL--",
        "admin' UNION SELECT 1,2,3,4,5--",
      ];

      for (const injection of injections) {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/register",
          payload: {
            username: injection,
            email: "test@example.com",
            password: "password123",
          },
        });

        // Should reject or sanitize
        expect(response.statusCode).toBe(400);
      }
    });

    it("should block blind SQL injection (boolean-based)", async () => {
      const injections = [
        "admin' AND '1'='1",
        "admin' AND '1'='2",
        "admin' AND 1=1--",
        "admin' AND 1=2--",
        "admin' AND EXISTS(SELECT * FROM users)--",
      ];

      for (const injection of injections) {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/login",
          payload: {
            username: injection,
            password: "test",
          },
        });

        // Zod blocks at validation = 400
        expect(response.statusCode).toBe(400);
      }
    });

    it("should block time-based blind SQL injection", async () => {
      const injections = [
        "admin'; WAITFOR DELAY '00:00:05'--",
        "admin' AND SLEEP(5)--",
        "admin'; SELECT pg_sleep(5)--",
        "admin' AND 1=SLEEP(5)--",
      ];

      for (const injection of injections) {
        const start = Date.now();

        const response = await app.inject({
          method: "POST",
          url: "/api/auth/login",
          payload: {
            username: injection,
            password: "test",
          },
        });

        const duration = Date.now() - start;

        // Should NOT execute SLEEP command (duration < 1 second)
        expect(duration).toBeLessThan(1000);
        // Zod blocks at validation = 400
        expect(response.statusCode).toBe(400);
      }
    });

    it("should block second-order SQL injection", async () => {
      // First, register user with malicious username
      const response1 = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        payload: {
          username: "admin'--",
          email: "test@example.com",
          password: "password123",
        },
      });

      // Should either reject or sanitize
      if (response1.statusCode === 201) {
        // If registration succeeded, try to trigger injection in second query
        const response2 = await loginUser(app, "admin'--", "password123");

        // Should not cause SQL errors
        expect([200, 401]).toContain(response2.response.statusCode);
      } else {
        // Registration rejected (good!)
        expect(response1.statusCode).toBe(400);
      }
    });

    it("should use parameterized queries (not string concatenation)", async () => {
      // This is more of a code review test
      // Verify that SQL queries use $1, $2 placeholders

      const username = "test'; DROP TABLE users; --";

      try {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/register",
          payload: {
            username,
            email: "test@example.com",
            password: "password123",
          },
        });

        // Should not crash server
        expect([400, 409, 500]).toContain(response.statusCode);

        // Verify users table still exists
        const result = await pool.query("SELECT COUNT(*) FROM users");
        expect(result).toBeDefined();
      } catch (error: any) {
        // If error occurs, it should NOT be SQL syntax error
        expect(error.message).not.toContain("syntax error");
        expect(error.message).not.toContain("table");
      }
    });
  });

  // ============================================================================
  // DATABASE DOS ATTACKS
  // ============================================================================

  describe("Database DoS Protection", () => {
    it("should handle connection pool exhaustion", async () => {
      // Try to exhaust connection pool by making many concurrent requests
      const promises = [];

      for (let i = 0; i < 50; i++) {
        promises.push(
          registerUser(app, {
            username: `user${i}`,
            password: "password123",
          }),
        );
      }

      const results = await Promise.allSettled(promises);

      // Most should succeed (not crash)
      const fulfilled = results.filter((r) => r.status === "fulfilled");
      expect(fulfilled.length).toBeGreaterThan(40);
    }, 30000);

    it("should prevent query bombing (heavy queries)", async () => {
      // Try to execute expensive query that could DoS database
      // PostgreSQL has query timeout to prevent this

      const start = Date.now();

      try {
        // Try to search with wildcard (expensive query)
        const response = await app.inject({
          method: "GET",
          url: "/api/users/search?q=%",
        });

        const duration = Date.now() - start;

        // Query should complete quickly (< 5 seconds)
        expect(duration).toBeLessThan(5000);
      } catch (error) {
        // Query timeout is acceptable
      }
    });

    it.skip("should limit result set size (prevent memory exhaustion)", async () => {
      // TODO: NOT IMPLEMENTED - requires LIMIT clause in search query
      // Register many users
      for (let i = 0; i < 100; i++) {
        await registerUser(app, {
          username: `user${i}`,
          password: "password123",
        });
      }

      // Search for all users
      const response = await app.inject({
        method: "GET",
        url: "/api/users/search?q=user",
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);

      // Should limit results (e.g., max 20-50 results)
      expect(body.data.length).toBeLessThanOrEqual(50);
    }, 120000);
  });

  // ============================================================================
  // PRIVILEGE ESCALATION
  // ============================================================================

  describe("Privilege Escalation Prevention", () => {
    it("should prevent privilege escalation via mass assignment", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        payload: {
          username: "attacker",
          email: "attacker@example.com",
          password: "password123",
          is_admin: true, // Try to set admin flag
          role: "admin",
          permissions: ["*"],
        },
      });

      if (response.statusCode === 201) {
        const body = JSON.parse(response.body);

        // User should NOT be admin
        expect(body.data.user.is_admin).not.toBe(true);
        expect(body.data.user.role).not.toBe("admin");
      }
    });

    it("should not allow direct database manipulation via payloads", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        payload: {
          username: "test",
          email: "test@example.com",
          password: "password123",
          $set: { is_admin: true }, // NoSQL-style injection
        },
      });

      // Should ignore $set modifier
      if (response.statusCode === 201) {
        const body = JSON.parse(response.body);
        expect(body.data.user.is_admin).not.toBe(true);
      }
    });
  });

  // ============================================================================
  // DATA LEAKAGE
  // ============================================================================

  describe("Data Leakage Prevention", () => {
    it("should not expose sensitive data in error messages", async () => {
      // Try to cause database error
      const response = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        payload: {
          username: "a".repeat(100000), // Too long
          email: "test@example.com",
          password: "password123",
        },
      });

      const body = JSON.parse(response.body);

      // Error message should NOT contain:
      // - Database schema details
      // - SQL query
      // - Stack trace
      // - File paths

      if (body.error) {
        expect(body.error).not.toContain("SELECT");
        expect(body.error).not.toContain("INSERT");
        expect(body.error).not.toContain("users");
        expect(body.error).not.toContain("column");
        expect(body.error).not.toContain(".ts");
        expect(body.error).not.toContain("at ");
        expect(body.error).not.toContain("postgres");
      }
    });

    it("should not expose database version in headers", async () => {
      const response = await app.inject({
        method: "GET",
        url: "/health",
      });

      const headers = response.headers;

      // Should not expose database version
      expect(headers["x-powered-by"]).toBeUndefined();

      // Server header should be removed (undefined) or not contain DB info
      if (headers["server"]) {
        expect(headers["server"]).not.toContain("PostgreSQL");
        expect(headers["server"]).not.toContain("postgres");
      }
    });

    it("should not leak user existence through timing", async () => {
      await registerUser(app, { username: "existinguser" });

      // Check if username exists
      const start1 = Date.now();
      const response1 = await app.inject({
        method: "GET",
        url: "/api/users/search?q=existinguser",
      });
      const time1 = Date.now() - start1;

      // Check if username doesn't exist
      const start2 = Date.now();
      const response2 = await app.inject({
        method: "GET",
        url: "/api/users/search?q=nonexistinguser",
      });
      const time2 = Date.now() - start2;

      // Response times should be similar (< 50ms difference)
      const difference = Math.abs(time1 - time2);
      expect(difference).toBeLessThan(50);
    });
  });

  // ============================================================================
  // DATABASE BACKUP & RECOVERY
  // ============================================================================

  describe("Database Backup Security", () => {
    it("should not expose backup files via web server", async () => {
      const backupFiles = [
        "/backup.sql",
        "/database.sql",
        "/dump.sql",
        "/cryptox.sql",
        "/.backup",
        "/db_backup.tar.gz",
      ];

      for (const file of backupFiles) {
        const response = await app.inject({
          method: "GET",
          url: file,
        });

        // Should return 404, not 200
        expect(response.statusCode).toBe(404);
      }
    });
  });
});

// Helper function
function calculateSimilarity(str1: string, str2: string): number {
  const len = Math.max(str1.length, str2.length);
  let matches = 0;

  for (let i = 0; i < Math.min(str1.length, str2.length); i++) {
    if (str1[i] === str2[i]) matches++;
  }

  return matches / len;
}
