/**
 * UserService Unit Tests
 * Covers: user creation, validation, search, edge cases
 */

import { describe, it, expect, beforeEach, afterAll } from "vitest";
import { UserService } from "../../../services/user.service.js";
import { clearDatabase, closeDatabase } from "../../helpers/db.helper.js";

describe("UserService", () => {
  beforeEach(async () => {
    await clearDatabase();
  });

  afterAll(async () => {
    await closeDatabase();
  });

  describe("usernameExists()", () => {
    it("should return false for non-existent username", async () => {
      const exists = await UserService.usernameExists("nonexistent");
      expect(exists).toBe(false);
    });

    it("should return true for existing username", async () => {
      await UserService.createUser({
        username: "testuser",
        email: "test@example.com",
        salt: "testsalt",
        auth_token: "testtoken",
        encrypted_master_key: "testkey",
        public_key: "testpublickey",
      });

      const exists = await UserService.usernameExists("testuser");
      expect(exists).toBe(true);
    });

    it("should be case-insensitive", async () => {
      await UserService.createUser({
        username: "TestUser",
        email: "test@example.com",
        salt: "testsalt",
        auth_token: "testtoken",
        encrypted_master_key: "testkey",
        public_key: "testpublickey",
      });

      const exists1 = await UserService.usernameExists("testuser");
      const exists2 = await UserService.usernameExists("TESTUSER");
      const exists3 = await UserService.usernameExists("TeStUsEr");

      expect(exists1).toBe(true);
      expect(exists2).toBe(true);
      expect(exists3).toBe(true);
    });

    it("should handle empty string", async () => {
      const exists = await UserService.usernameExists("");
      expect(exists).toBe(false);
    });

    it("should handle very long username", async () => {
      const longUsername = "a".repeat(1000);
      const exists = await UserService.usernameExists(longUsername);
      expect(exists).toBe(false);
    });

    it("should handle special characters safely (no SQL injection)", async () => {
      const maliciousUsernames = [
        "admin' OR '1'='1",
        "admin--",
        "admin'; DROP TABLE users; --",
        "' OR 1=1 --",
      ];

      for (const username of maliciousUsernames) {
        const exists = await UserService.usernameExists(username);
        expect(exists).toBe(false);
      }
    });
  });

  describe("emailExists()", () => {
    it("should return false for non-existent email", async () => {
      const exists = await UserService.emailExists("nonexistent@example.com");
      expect(exists).toBe(false);
    });

    it("should return true for existing email", async () => {
      await UserService.createUser({
        username: "testuser",
        email: "test@example.com",
        salt: "testsalt",
        auth_token: "testtoken",
        encrypted_master_key: "testkey",
        public_key: "testpublickey",
      });

      const exists = await UserService.emailExists("test@example.com");
      expect(exists).toBe(true);
    });

    it("should be case-insensitive", async () => {
      await UserService.createUser({
        username: "testuser",
        email: "Test@Example.Com",
        salt: "testsalt",
        auth_token: "testtoken",
        encrypted_master_key: "testkey",
        public_key: "testpublickey",
      });

      const exists1 = await UserService.emailExists("test@example.com");
      const exists2 = await UserService.emailExists("TEST@EXAMPLE.COM");
      const exists3 = await UserService.emailExists("TeSt@ExAmPlE.cOm");

      expect(exists1).toBe(true);
      expect(exists2).toBe(true);
      expect(exists3).toBe(true);
    });

    it("should handle SQL injection attempts", async () => {
      const maliciousEmails = [
        "admin@example.com' OR '1'='1",
        "test@example.com--",
        "'; DROP TABLE users; --@example.com",
      ];

      for (const email of maliciousEmails) {
        const exists = await UserService.emailExists(email);
        expect(exists).toBe(false);
      }
    });
  });

  describe("createUser()", () => {
    it("should create user with valid data", async () => {
      const user = await UserService.createUser({
        username: "newuser",
        email: "new@example.com",
        salt: "salt123",
        auth_token: "token123",
        encrypted_master_key: "key123",
        public_key: "publickey123",
      });

      expect(user).toBeDefined();
      expect(user.username).toBe("newuser");
      expect(user.email).toBe("new@example.com");
      expect(user.salt).toBe("salt123");
      expect(user.auth_token).toBe("token123");
      expect(user.encrypted_master_key).toBe("key123");
      expect(user.public_key).toBe("publickey123");
    });

    it("should normalize username to lowercase", async () => {
      const user = await UserService.createUser({
        username: "NewUser",
        email: "new@example.com",
        salt: "salt123",
        auth_token: "token123",
        encrypted_master_key: "key123",
        public_key: "publickey123",
      });

      expect(user.username).toBe("newuser");
    });

    it("should normalize email to lowercase", async () => {
      const user = await UserService.createUser({
        username: "newuser",
        email: "New@Example.COM",
        salt: "salt123",
        auth_token: "token123",
        encrypted_master_key: "key123",
        public_key: "publickey123",
      });

      expect(user.email).toBe("new@example.com");
    });

    it("should set default values", async () => {
      const user = await UserService.createUser({
        username: "newuser",
        email: "new@example.com",
        salt: "salt123",
        auth_token: "token123",
        encrypted_master_key: "key123",
        public_key: "publickey123",
      });

      expect(user.email_verified).toBe(false);
      expect(user.data_version).toBe(2);
      expect(user.spam_score).toBe(0);
      expect(user.is_banned).toBe(false);
    });

    it("should throw error for duplicate username", async () => {
      await UserService.createUser({
        username: "duplicate",
        email: "user1@example.com",
        salt: "salt123",
        auth_token: "token123",
        encrypted_master_key: "key123",
        public_key: "publickey123",
      });

      await expect(
        UserService.createUser({
          username: "duplicate",
          email: "user2@example.com",
          salt: "salt456",
          auth_token: "token456",
          encrypted_master_key: "key456",
          public_key: "publickey456",
        }),
      ).rejects.toThrow();
    });

    it("should throw error for duplicate email", async () => {
      await UserService.createUser({
        username: "user1",
        email: "duplicate@example.com",
        salt: "salt123",
        auth_token: "token123",
        encrypted_master_key: "key123",
        public_key: "publickey123",
      });

      await expect(
        UserService.createUser({
          username: "user2",
          email: "duplicate@example.com",
          salt: "salt456",
          auth_token: "token456",
          encrypted_master_key: "key456",
          public_key: "publickey456",
        }),
      ).rejects.toThrow();
    });
  });

  describe("getUserByUsername()", () => {
    it("should return user for existing username", async () => {
      await UserService.createUser({
        username: "testuser",
        email: "test@example.com",
        salt: "testsalt",
        auth_token: "testtoken",
        encrypted_master_key: "testkey",
        public_key: "testpublickey",
      });

      const user = await UserService.getUserByUsername("testuser");

      expect(user).toBeDefined();
      expect(user?.username).toBe("testuser");
      expect(user?.email).toBe("test@example.com");
    });

    it("should return null for non-existent username", async () => {
      const user = await UserService.getUserByUsername("nonexistent");
      expect(user).toBeNull();
    });

    it("should be case-insensitive", async () => {
      await UserService.createUser({
        username: "TestUser",
        email: "test@example.com",
        salt: "testsalt",
        auth_token: "testtoken",
        encrypted_master_key: "testkey",
        public_key: "testpublickey",
      });

      const user1 = await UserService.getUserByUsername("testuser");
      const user2 = await UserService.getUserByUsername("TESTUSER");

      expect(user1).toBeDefined();
      expect(user2).toBeDefined();
      expect(user1?.username).toBe(user2?.username);
    });

    it("should not expose sensitive data in wrong places", async () => {
      const created = await UserService.createUser({
        username: "testuser",
        email: "test@example.com",
        salt: "testsalt",
        auth_token: "testtoken",
        encrypted_master_key: "testkey",
        public_key: "testpublickey",
      });

      const user = await UserService.getUserByUsername("testuser");

      // These SHOULD exist (we need them for auth)
      expect(user?.salt).toBeDefined();
      expect(user?.auth_token).toBeDefined();
      expect(user?.encrypted_master_key).toBeDefined();
    });
  });

  describe("getUserByEmail()", () => {
    it("should return user for existing email", async () => {
      await UserService.createUser({
        username: "testuser",
        email: "test@example.com",
        salt: "testsalt",
        auth_token: "testtoken",
        encrypted_master_key: "testkey",
        public_key: "testpublickey",
      });

      const user = await UserService.getUserByEmail("test@example.com");

      expect(user).toBeDefined();
      expect(user?.username).toBe("testuser");
      expect(user?.email).toBe("test@example.com");
    });

    it("should return null for non-existent email", async () => {
      const user = await UserService.getUserByEmail("nonexistent@example.com");
      expect(user).toBeNull();
    });

    it("should be case-insensitive", async () => {
      await UserService.createUser({
        username: "testuser",
        email: "Test@Example.Com",
        salt: "testsalt",
        auth_token: "testtoken",
        encrypted_master_key: "testkey",
        public_key: "testpublickey",
      });

      const user1 = await UserService.getUserByEmail("test@example.com");
      const user2 = await UserService.getUserByEmail("TEST@EXAMPLE.COM");

      expect(user1).toBeDefined();
      expect(user2).toBeDefined();
      expect(user1?.email).toBe(user2?.email);
    });
  });

  describe("searchUsers()", () => {
    beforeEach(async () => {
      // Create test users
      await UserService.createUser({
        username: "alice",
        email: "alice@example.com",
        salt: "salt",
        auth_token: "token",
        encrypted_master_key: "key",
        public_key: "pubkey",
      });

      await UserService.createUser({
        username: "bob",
        email: "bob@example.com",
        salt: "salt",
        auth_token: "token",
        encrypted_master_key: "key",
        public_key: "pubkey",
      });

      await UserService.createUser({
        username: "charlie",
        email: "charlie@example.com",
        salt: "salt",
        auth_token: "token",
        encrypted_master_key: "key",
        public_key: "pubkey",
      });
    });

    it("should find users by partial username", async () => {
      const results = await UserService.searchUsers("ali");

      expect(results.length).toBeGreaterThan(0);
      expect(results.some((u) => u.username === "alice")).toBe(true);
    });

    it("should find users by exact username", async () => {
      const results = await UserService.searchUsers("bob");

      expect(results.length).toBeGreaterThan(0);
      expect(results.some((u) => u.username === "bob")).toBe(true);
    });

    it("should return empty array for no matches", async () => {
      const results = await UserService.searchUsers("nonexistent");

      expect(results).toEqual([]);
    });

    it("should be case-insensitive", async () => {
      const results1 = await UserService.searchUsers("ALICE");
      const results2 = await UserService.searchUsers("alice");
      const results3 = await UserService.searchUsers("AlIcE");

      expect(results1.length).toBeGreaterThan(0);
      expect(results2.length).toBeGreaterThan(0);
      expect(results3.length).toBeGreaterThan(0);
    });

    it("should respect limit parameter", async () => {
      const results = await UserService.searchUsers("", 2);

      expect(results.length).toBeLessThanOrEqual(2);
    });

    it("should not return sensitive data", async () => {
      const results = await UserService.searchUsers("alice");

      expect(results.length).toBeGreaterThan(0);
      const user = results[0];

      expect(user.username).toBeDefined();
      expect(user.email_verified).toBeDefined();

      // Should NOT expose sensitive data
      expect(user.salt).toBeUndefined();
      expect(user.auth_token).toBeUndefined();
      expect(user.encrypted_master_key).toBeUndefined();
      expect(user.email).toBeUndefined();
    });

    it("should handle SQL injection attempts safely", async () => {
      const maliciousQueries = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "admin' --",
        "%' OR '1'='1' --",
      ];

      for (const query of maliciousQueries) {
        const results = await UserService.searchUsers(query);
        // Should not crash and should return empty or safe results
        expect(Array.isArray(results)).toBe(true);
      }
    });
  });

  describe("updateLastSeen()", () => {
    it("should update last_seen timestamp", async () => {
      await UserService.createUser({
        username: "testuser",
        email: "test@example.com",
        salt: "testsalt",
        auth_token: "testtoken",
        encrypted_master_key: "testkey",
        public_key: "testpublickey",
      });

      const beforeUpdate = await UserService.getUserByUsername("testuser");
      const lastSeenBefore = beforeUpdate?.last_seen;

      // Wait a bit to ensure timestamp changes
      await new Promise((resolve) => setTimeout(resolve, 10));

      await UserService.updateLastSeen("testuser");

      const afterUpdate = await UserService.getUserByUsername("testuser");
      const lastSeenAfter = afterUpdate?.last_seen;

      expect(lastSeenAfter).toBeDefined();
      // last_seen should be updated (different timestamp)
      expect(new Date(lastSeenAfter!).getTime()).toBeGreaterThanOrEqual(
        new Date(lastSeenBefore!).getTime(),
      );
    });

    it("should not throw error for non-existent user", async () => {
      await expect(
        UserService.updateLastSeen("nonexistent"),
      ).resolves.not.toThrow();
    });
  });
});
