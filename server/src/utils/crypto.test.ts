import { describe, it, expect } from "vitest";
import {
  generateSalt,
  generateMasterKey,
  generateVerificationCode,
  hashPassword,
  generateAuthToken,
  generateEmailRecoveryKey,
  deriveStorageKey,
  encrypt,
  decrypt,
  isValidUsername,
  isValidEmail,
  isValidPassword,
} from "./crypto.js";

describe("Server Crypto - Salt & Key Generation", () => {
  it("should generate a salt (hex format)", () => {
    const salt = generateSalt();

    expect(salt).toBeDefined();
    expect(typeof salt).toBe("string");
    // 32 bytes in hex = 64 characters
    expect(salt.length).toBe(64);
  });

  it("should generate unique salts", () => {
    const salt1 = generateSalt();
    const salt2 = generateSalt();
    const salt3 = generateSalt();

    expect(salt1).not.toBe(salt2);
    expect(salt2).not.toBe(salt3);
  });

  it("should generate a master key (hex format)", () => {
    const masterKey = generateMasterKey();

    expect(masterKey).toBeDefined();
    expect(typeof masterKey).toBe("string");
    // 32 bytes in hex = 64 characters
    expect(masterKey.length).toBe(64);
  });

  it("should generate unique master keys", () => {
    const key1 = generateMasterKey();
    const key2 = generateMasterKey();

    expect(key1).not.toBe(key2);
  });

  it("should generate 6-digit verification code", () => {
    const code = generateVerificationCode();

    expect(code).toBeDefined();
    expect(typeof code).toBe("string");
    expect(code.length).toBe(6);
    expect(Number(code)).toBeGreaterThanOrEqual(100000);
    expect(Number(code)).toBeLessThanOrEqual(999999);
  });
});

describe("Server Crypto - Argon2 Password Hashing", () => {
  it("should hash password with Argon2id", async () => {
    const password = "mySecurePassword123";
    const salt = generateSalt();

    const hash = await hashPassword(password, salt);

    expect(hash).toBeDefined();
    expect(typeof hash).toBe("string");
    expect(hash.length).toBeGreaterThan(0);
  });

  it("should produce same hash for same password + salt", async () => {
    const password = "testPassword";
    const salt = generateSalt();

    const hash1 = await hashPassword(password, salt);
    const hash2 = await hashPassword(password, salt);

    expect(hash1).toBe(hash2);
  });

  it("should produce different hashes for different salts", async () => {
    const password = "testPassword";
    const salt1 = generateSalt();
    const salt2 = generateSalt();

    const hash1 = await hashPassword(password, salt1);
    const hash2 = await hashPassword(password, salt2);

    expect(hash1).not.toBe(hash2);
  });

  it("should produce different hashes for different passwords", async () => {
    const salt = generateSalt();

    const hash1 = await hashPassword("password1", salt);
    const hash2 = await hashPassword("password2", salt);

    expect(hash1).not.toBe(hash2);
  });

  it("should take reasonable time (Argon2 is slow by design)", async () => {
    const start = Date.now();
    await hashPassword("test", generateSalt());
    const end = Date.now();

    // Should take at least 50ms (security feature, varies by CPU)
    expect(end - start).toBeGreaterThan(50);
  });
}, 30000); // 30s timeout for slow Argon2

describe("Server Crypto - Auth Token Generation", () => {
  it("should generate auth token from password key", () => {
    const passwordKey = "a".repeat(64); // mock password hash
    const token = generateAuthToken(passwordKey);

    expect(token).toBeDefined();
    expect(typeof token).toBe("string");
    expect(token.length).toBeGreaterThan(0);
  });

  it("should produce same token for same password key", () => {
    const passwordKey = "test_key_123";

    const token1 = generateAuthToken(passwordKey);
    const token2 = generateAuthToken(passwordKey);

    expect(token1).toBe(token2);
  });

  it("should produce different tokens for different keys", () => {
    // Use valid hex strings (64 chars = 32 bytes)
    const key1 = "a".repeat(64);
    const key2 = "b".repeat(64);

    const token1 = generateAuthToken(key1);
    const token2 = generateAuthToken(key2);

    expect(token1).not.toBe(token2);
  });
});

describe("Server Crypto - Email Recovery Key", () => {
  it("should generate email recovery key", async () => {
    const email = "test@example.com";
    const serverSecret = "test_server_secret";

    const key = await generateEmailRecoveryKey(email, serverSecret);

    expect(key).toBeDefined();
    expect(typeof key).toBe("string");
    expect(key.length).toBeGreaterThan(0);
  });

  it("should produce same key for same email + secret", async () => {
    const email = "test@example.com";
    const secret = "secret";

    const key1 = await generateEmailRecoveryKey(email, secret);
    const key2 = await generateEmailRecoveryKey(email, secret);

    expect(key1).toBe(key2);
  });

  it("should produce different keys for different emails", async () => {
    const secret = "secret";

    const key1 = await generateEmailRecoveryKey("alice@example.com", secret);
    const key2 = await generateEmailRecoveryKey("bob@example.com", secret);

    expect(key1).not.toBe(key2);
  });

  it("should handle lowercase email", async () => {
    const secret = "secret";

    const key1 = await generateEmailRecoveryKey("Test@Example.com", secret);
    const key2 = await generateEmailRecoveryKey("test@example.com", secret);

    // Should be the same (email normalized to lowercase)
    expect(key1).toBe(key2);
  });
}, 30000);

describe("Server Crypto - Storage Key Derivation", () => {
  it("should derive storage key from master key", () => {
    const masterKey = generateMasterKey();
    const storageKey = deriveStorageKey(masterKey);

    expect(storageKey).toBeDefined();
    expect(typeof storageKey).toBe("string");
  });

  it("should produce same storage key for same master key", () => {
    // Use valid hex string (64 chars = 32 bytes)
    const masterKey = "a".repeat(64);

    const key1 = deriveStorageKey(masterKey);
    const key2 = deriveStorageKey(masterKey);

    expect(key1).toBe(key2);
  });
});

describe("Server Crypto - Encryption/Decryption", () => {
  it("should encrypt data", () => {
    const data = "sensitive data";
    const key = generateMasterKey();

    const result = encrypt(data, key);

    expect(result).toBeDefined();
    expect(result.ciphertext).toBeDefined();
    expect(result.nonce).toBeDefined();
    expect(typeof result.ciphertext).toBe("string");
    expect(typeof result.nonce).toBe("string");
  });

  it("should decrypt encrypted data", () => {
    const originalData = "Master Key 12345";
    const key = generateMasterKey();

    const { ciphertext, nonce } = encrypt(originalData, key);
    const decrypted = decrypt(ciphertext, nonce, key);

    expect(decrypted).toBe(originalData);
  });

  it("should fail to decrypt with wrong key", () => {
    const data = "secret";
    const key1 = generateMasterKey();
    const key2 = generateMasterKey();

    const { ciphertext, nonce } = encrypt(data, key1);
    const decrypted = decrypt(ciphertext, nonce, key2);

    expect(decrypted).toBeNull();
  });

  it("should fail to decrypt with wrong nonce", () => {
    const data = "secret";
    const key = generateMasterKey();

    const { ciphertext } = encrypt(data, key);
    // Generate wrong nonce (24 bytes = 48 hex chars, not 32 bytes like salt)
    const wrongNonce = "0".repeat(48);
    const decrypted = decrypt(ciphertext, wrongNonce, key);

    expect(decrypted).toBeNull();
  });

  it("should handle empty data", () => {
    const data = "";
    const key = generateMasterKey();

    const { ciphertext, nonce } = encrypt(data, key);
    const decrypted = decrypt(ciphertext, nonce, key);

    expect(decrypted).toBe("");
  });

  it("should handle unicode and emoji", () => {
    const data = "Секрет 🔐";
    const key = generateMasterKey();

    const { ciphertext, nonce } = encrypt(data, key);
    const decrypted = decrypt(ciphertext, nonce, key);

    expect(decrypted).toBe(data);
  });

  it("should generate unique nonces", () => {
    const data = "same data";
    const key = generateMasterKey();

    const result1 = encrypt(data, key);
    const result2 = encrypt(data, key);
    const result3 = encrypt(data, key);

    expect(result1.nonce).not.toBe(result2.nonce);
    expect(result2.nonce).not.toBe(result3.nonce);
  });
});

describe("Server Validation - Username", () => {
  it("should accept valid usernames", () => {
    expect(isValidUsername("alice")).toBe(true);
    expect(isValidUsername("bob123")).toBe(true);
    expect(isValidUsername("user_name")).toBe(true);
    expect(isValidUsername("abc")).toBe(true);
    expect(isValidUsername("a".repeat(30))).toBe(true);
  });

  it("should reject invalid usernames", () => {
    expect(isValidUsername("ab")).toBe(false); // too short
    expect(isValidUsername("a".repeat(31))).toBe(false); // too long
    expect(isValidUsername("Alice")).toBe(false); // uppercase
    expect(isValidUsername("user-name")).toBe(false);
    expect(isValidUsername("")).toBe(false);
  });
});

describe("Server Validation - Email", () => {
  it("should accept valid emails", () => {
    expect(isValidEmail("user@example.com")).toBe(true);
    expect(isValidEmail("test@mail.ru")).toBe(true);
  });

  it("should reject invalid emails", () => {
    expect(isValidEmail("notanemail")).toBe(false);
    expect(isValidEmail("")).toBe(false);
  });
});

describe("Server Validation - Password", () => {
  it("should accept valid passwords", () => {
    expect(isValidPassword("12345678")).toBe(true);
    expect(isValidPassword("password")).toBe(true);
  });

  it("should reject short passwords", () => {
    expect(isValidPassword("1234567")).toBe(false);
    expect(isValidPassword("")).toBe(false);
  });
});
