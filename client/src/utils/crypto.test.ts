import { describe, it, expect } from "vitest";
import {
  generateKey,
  generateSessionKey,
  encryptMessage,
  decryptMessage,
  generateSalt,
  isValidUsername,
  isValidEmail,
  isValidPassword,
} from "./crypto";

describe("Crypto Utils - Key Generation", () => {
  it("should generate a 32-byte key (base64 encoded)", () => {
    const key = generateKey();

    expect(key).toBeDefined();
    expect(typeof key).toBe("string");
    expect(key.length).toBeGreaterThan(0);

    // Base64 encoded 32 bytes should be ~44 characters
    expect(key.length).toBeGreaterThanOrEqual(40);
  });

  it("should generate unique keys each time", () => {
    const key1 = generateKey();
    const key2 = generateKey();
    const key3 = generateKey();

    expect(key1).not.toBe(key2);
    expect(key2).not.toBe(key3);
    expect(key1).not.toBe(key3);
  });

  it("should generate a session key", () => {
    const sessionKey = generateSessionKey();

    expect(sessionKey).toBeDefined();
    expect(typeof sessionKey).toBe("string");
    expect(sessionKey.length).toBeGreaterThanOrEqual(40);
  });
});

describe("Crypto Utils - Encryption/Decryption", () => {
  it("should encrypt a message and return ciphertext + nonce", () => {
    const message = "Hello, World!";
    const key = generateKey();

    const result = encryptMessage(message, key);

    expect(result).toBeDefined();
    expect(result.ciphertext).toBeDefined();
    expect(result.nonce).toBeDefined();
    expect(typeof result.ciphertext).toBe("string");
    expect(typeof result.nonce).toBe("string");
  });

  it("should decrypt an encrypted message correctly", () => {
    const originalMessage = "Secret message 🔐";
    const key = generateKey();

    const { ciphertext, nonce } = encryptMessage(originalMessage, key);
    const decrypted = decryptMessage(ciphertext, nonce, key);

    expect(decrypted).toBe(originalMessage);
  });

  it("should fail to decrypt with wrong key", () => {
    const message = "Secret";
    const key1 = generateKey();
    const key2 = generateKey();

    const { ciphertext, nonce } = encryptMessage(message, key1);
    const decrypted = decryptMessage(ciphertext, nonce, key2);

    expect(decrypted).toBeNull();
  });

  it("should fail to decrypt with wrong nonce", () => {
    const message = "Secret";
    const key = generateKey();

    const { ciphertext } = encryptMessage(message, key);
    const wrongNonce = generateSalt(); // Using salt as fake nonce
    const decrypted = decryptMessage(ciphertext, wrongNonce, key);

    expect(decrypted).toBeNull();
  });

  it("should handle empty message", () => {
    const message = "";
    const key = generateKey();

    const { ciphertext, nonce } = encryptMessage(message, key);
    const decrypted = decryptMessage(ciphertext, nonce, key);

    expect(decrypted).toBe("");
  });

  it("should handle unicode characters (emoji)", () => {
    const message = "Привет мир! 🚀🔐💻";
    const key = generateKey();

    const { ciphertext, nonce } = encryptMessage(message, key);
    const decrypted = decryptMessage(ciphertext, nonce, key);

    expect(decrypted).toBe(message);
  });

  it("should handle very long messages", () => {
    const message = "A".repeat(10000); // 10KB message
    const key = generateKey();

    const { ciphertext, nonce } = encryptMessage(message, key);
    const decrypted = decryptMessage(ciphertext, nonce, key);

    expect(decrypted).toBe(message);
  });

  it("should generate unique nonces for same message", () => {
    const message = "Same message";
    const key = generateKey();

    const result1 = encryptMessage(message, key);
    const result2 = encryptMessage(message, key);
    const result3 = encryptMessage(message, key);

    // Nonces must be different (critical for security!)
    expect(result1.nonce).not.toBe(result2.nonce);
    expect(result2.nonce).not.toBe(result3.nonce);
    expect(result1.nonce).not.toBe(result3.nonce);
  });
});

describe("Crypto Utils - Salt Generation", () => {
  it("should generate a salt", () => {
    const salt = generateSalt();

    expect(salt).toBeDefined();
    expect(typeof salt).toBe("string");
    expect(salt.length).toBeGreaterThan(0);
  });

  it("should generate unique salts", () => {
    const salt1 = generateSalt();
    const salt2 = generateSalt();
    const salt3 = generateSalt();

    expect(salt1).not.toBe(salt2);
    expect(salt2).not.toBe(salt3);
    expect(salt1).not.toBe(salt3);
  });
});

describe("Validation - Username", () => {
  it("should accept valid usernames", () => {
    expect(isValidUsername("alice")).toBe(true);
    expect(isValidUsername("bob123")).toBe(true);
    expect(isValidUsername("user_name")).toBe(true);
    expect(isValidUsername("abc")).toBe(true); // minimum 3 chars
    expect(isValidUsername("a".repeat(30))).toBe(true); // maximum 30 chars
  });

  it("should reject invalid usernames", () => {
    expect(isValidUsername("ab")).toBe(false); // too short
    expect(isValidUsername("a".repeat(31))).toBe(false); // too long
    expect(isValidUsername("Alice")).toBe(false); // uppercase
    expect(isValidUsername("user-name")).toBe(false); // hyphen not allowed
    expect(isValidUsername("user name")).toBe(false); // space not allowed
    expect(isValidUsername("user@name")).toBe(false); // @ not allowed
    expect(isValidUsername("")).toBe(false); // empty
  });
});

describe("Validation - Email", () => {
  it("should accept valid emails", () => {
    expect(isValidEmail("user@example.com")).toBe(true);
    expect(isValidEmail("test.user@domain.co.uk")).toBe(true);
    expect(isValidEmail("name+tag@mail.ru")).toBe(true);
    expect(isValidEmail("admin@localhost.dev")).toBe(true);
  });

  it("should reject invalid emails", () => {
    expect(isValidEmail("notanemail")).toBe(false);
    expect(isValidEmail("missing@domain")).toBe(false);
    expect(isValidEmail("@nodomain.com")).toBe(false);
    expect(isValidEmail("user@")).toBe(false);
    expect(isValidEmail("user @domain.com")).toBe(false); // space
    expect(isValidEmail("")).toBe(false);
  });
});

describe("Validation - Password", () => {
  it("should accept valid passwords", () => {
    expect(isValidPassword("12345678")).toBe(true); // minimum 8 chars
    expect(isValidPassword("password")).toBe(true);
    expect(isValidPassword("P@ssw0rd!")).toBe(true);
    expect(isValidPassword("a".repeat(100))).toBe(true); // long password
  });

  it("should reject invalid passwords", () => {
    expect(isValidPassword("1234567")).toBe(false); // too short (7 chars)
    expect(isValidPassword("short")).toBe(false);
    expect(isValidPassword("")).toBe(false);
  });
});
