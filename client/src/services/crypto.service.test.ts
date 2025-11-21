import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { cryptoService } from "./crypto.service";

describe("CryptoService - Chat ID Creation", () => {
  it("should create deterministic chat ID", () => {
    const chatId1 = cryptoService.createChatId("alice", "bob");
    const chatId2 = cryptoService.createChatId("bob", "alice");

    // Must be the same regardless of order
    expect(chatId1).toBe(chatId2);
  });

  it("should sort usernames alphabetically", () => {
    const chatId = cryptoService.createChatId("zara", "alice");

    expect(chatId).toBe("alice_zara");
  });

  it("should handle same username (edge case)", () => {
    const chatId = cryptoService.createChatId("alice", "alice");

    expect(chatId).toBe("alice_alice");
  });
});

describe("CryptoService - Session Key Management", () => {
  beforeEach(() => {
    // Clear localStorage before each test
    localStorage.clear();
    cryptoService.clearSessionKeys();
  });

  afterEach(() => {
    localStorage.clear();
  });

  it("should generate and store session key for new chat", () => {
    const chatId = cryptoService.createChatId("alice", "bob");
    const key = cryptoService.getSessionKey(chatId);

    expect(key).toBeDefined();
    expect(typeof key).toBe("string");
    expect(key.length).toBeGreaterThan(0);
  });

  it("should return same key for same chat", () => {
    const chatId = cryptoService.createChatId("alice", "bob");
    const key1 = cryptoService.getSessionKey(chatId);
    const key2 = cryptoService.getSessionKey(chatId);

    expect(key1).toBe(key2);
  });

  it("should generate different keys for different chats", () => {
    const chatId1 = cryptoService.createChatId("alice", "bob");
    const chatId2 = cryptoService.createChatId("alice", "charlie");

    const key1 = cryptoService.getSessionKey(chatId1);
    const key2 = cryptoService.getSessionKey(chatId2);

    expect(key1).not.toBe(key2);
  });

  it("should persist keys in localStorage", () => {
    const chatId = cryptoService.createChatId("alice", "bob");
    const key = cryptoService.getSessionKey(chatId);

    // Keys are stored as individual items: session_key_${chatId}
    const stored = localStorage.getItem(`session_key_${chatId}`);
    expect(stored).toBeDefined();
    expect(stored).toBe(key);
  });

  it("should load keys from localStorage", () => {
    const chatId = cryptoService.createChatId("alice", "bob");

    // Manually store a key using the actual storage format
    const testKey = "test_session_key_12345";
    localStorage.setItem(`session_key_${chatId}`, testKey);

    // Load keys
    cryptoService.loadSessionKeys();

    // Should return the stored key
    const key = cryptoService.getSessionKey(chatId);
    expect(key).toBe(testKey);
  });

  it("should clear all session keys", () => {
    const chatId1 = cryptoService.createChatId("alice", "bob");
    const chatId2 = cryptoService.createChatId("alice", "charlie");

    cryptoService.getSessionKey(chatId1);
    cryptoService.getSessionKey(chatId2);

    expect(localStorage.getItem("cryptox_session_keys")).toBeDefined();

    cryptoService.clearSessionKeys();

    expect(localStorage.getItem("cryptox_session_keys")).toBeNull();
  });
});

describe("CryptoService - Message Encryption", () => {
  beforeEach(() => {
    localStorage.clear();
    cryptoService.clearSessionKeys();
  });

  it("should encrypt message for chat", () => {
    const message = "Hello, Bob!";
    const encrypted = cryptoService.encryptMessageForChat(
      message,
      "bob",
      "alice",
    );

    expect(encrypted).toBeDefined();
    expect(typeof encrypted).toBe("string");
    expect(encrypted).toContain(":"); // Format: ciphertext:nonce
  });

  it("should decrypt message from chat", () => {
    const originalMessage = "Secret message 🔐";
    const encrypted = cryptoService.encryptMessageForChat(
      originalMessage,
      "bob",
      "alice",
    );

    const decrypted = cryptoService.decryptMessageFromChat(
      encrypted,
      "alice",
      "bob",
    );

    expect(decrypted).toBe(originalMessage);
  });

  it("should use same session key for both directions", () => {
    const message = "Test";

    // Alice encrypts for Bob
    const encryptedAliceToBob = cryptoService.encryptMessageForChat(
      message,
      "bob",
      "alice",
    );

    // Bob should be able to decrypt
    const decryptedByBob = cryptoService.decryptMessageFromChat(
      encryptedAliceToBob,
      "alice",
      "bob",
    );

    expect(decryptedByBob).toBe(message);
  });

  it("should handle empty message", () => {
    const encrypted = cryptoService.encryptMessageForChat("", "bob", "alice");
    const decrypted = cryptoService.decryptMessageFromChat(
      encrypted,
      "alice",
      "bob",
    );

    expect(decrypted).toBe("");
  });

  it("should handle unicode and emoji", () => {
    const message = "Привет! 🚀💻🔐";
    const encrypted = cryptoService.encryptMessageForChat(
      message,
      "bob",
      "alice",
    );
    const decrypted = cryptoService.decryptMessageFromChat(
      encrypted,
      "alice",
      "bob",
    );

    expect(decrypted).toBe(message);
  });

  it("should return null for invalid encrypted content", () => {
    const invalidEncrypted = "invalid_format_no_colon";
    const decrypted = cryptoService.decryptMessageFromChat(
      invalidEncrypted,
      "alice",
      "bob",
    );

    expect(decrypted).toBeNull();
  });

  it("should fail to decrypt with different chat context", () => {
    // Alice encrypts for Bob
    const encrypted = cryptoService.encryptMessageForChat(
      "Secret",
      "bob",
      "alice",
    );

    // Charlie tries to decrypt (different chat ID)
    const decrypted = cryptoService.decryptMessageFromChat(
      encrypted,
      "alice",
      "charlie",
    );

    expect(decrypted).toBeNull();
  });
});
