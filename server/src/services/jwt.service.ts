import jwt from "jsonwebtoken";
import { randomUUID } from "crypto";
import { env } from "../config/env.js";
import { logger } from "./logger.service.js";

export interface JwtPayload {
  username: string;
  email: string;
  jti?: string; // JWT ID для уникальности
  iat?: number; // Issued at
  exp?: number; // Expires at
  nbf?: number; // Not before
}

/**
 * 🛡️ SECURE JWT SERVICE
 *
 * Protection against:
 * - "none" algorithm attack (CVE-2015-9235)
 * - Algorithm confusion (HS256 vs RS256)
 * - Weak/guessable secrets
 * - Token tampering
 * - Expired/future tokens
 * - Missing required claims
 */
export class JwtService {
  // Allowed algorithms (ONLY HS256 for HMAC with secret)
  private static readonly ALLOWED_ALGORITHMS = ["HS256"];

  // Minimum JWT secret length (256 bits = 32 bytes)
  private static readonly MIN_SECRET_LENGTH = 32;

  /**
   * Validate JWT secret strength
   */
  private static validateSecret(): void {
    const secret = env.JWT_SECRET;

    if (!secret) {
      throw new Error("JWT_SECRET is not defined");
    }

    if (secret.length < this.MIN_SECRET_LENGTH) {
      throw new Error(
        `JWT_SECRET must be at least ${this.MIN_SECRET_LENGTH} characters`,
      );
    }

    // Check if secret is weak/common
    const weakSecrets = [
      "secret",
      "password",
      "123456",
      "admin",
      "test",
      "changeme",
      "null",
      "undefined",
    ];

    if (weakSecrets.some((weak) => secret.toLowerCase().includes(weak))) {
      logger.warn(
        "JWT_SECRET appears to be weak - please use a strong random secret",
      );
    }
  }

  /**
   * Генерация JWT токена
   */
  static generate(payload: JwtPayload): string {
    // Validate secret on first use
    this.validateSecret();

    // Validate input payload
    if (!payload.username || !payload.email) {
      throw new Error("Username and email are required in JWT payload");
    }

    // Добавляем уникальный jti чтобы каждый токен был уникальным
    // (prevents session fixation attacks)
    const payloadWithJti = {
      ...payload,
      jti: randomUUID(),
    };

    return jwt.sign(payloadWithJti, env.JWT_SECRET, {
      algorithm: "HS256", // Explicitly set algorithm
      expiresIn: env.JWT_EXPIRES_IN,
      issuer: "cryptox-server", // Add issuer
      audience: "cryptox-client", // Add audience
    } as jwt.SignOptions);
  }

  /**
   * Проверка JWT токена
   */
  static verify(token: string): JwtPayload | null {
    try {
      // Validate secret
      this.validateSecret();

      // Basic validation
      if (!token || typeof token !== "string") {
        logger.warn("JWT verify: Invalid token format");
        return null;
      }

      // Check if token has 3 parts (header.payload.signature)
      const parts = token.split(".");
      if (parts.length !== 3) {
        logger.warn("JWT verify: Token must have 3 parts");
        return null;
      }

      // Decode header to check algorithm BEFORE verification
      let header: any;
      try {
        header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
      } catch (e) {
        logger.warn("JWT verify: Invalid token header");
        return null;
      }

      // CRITICAL: Reject "none" algorithm (CVE-2015-9235)
      if (!header.alg || header.alg.toLowerCase() === "none") {
        logger.error('JWT verify: "none" algorithm rejected');
        return null;
      }

      // CRITICAL: Only allow specific algorithms
      if (!this.ALLOWED_ALGORITHMS.includes(header.alg)) {
        logger.error(`JWT verify: Algorithm "${header.alg}" not allowed`);
        return null;
      }

      // Verify token with strict options
      const decoded = jwt.verify(token, env.JWT_SECRET, {
        algorithms: this.ALLOWED_ALGORITHMS as jwt.Algorithm[], // Only allow HS256
        issuer: "cryptox-server", // Verify issuer
        audience: "cryptox-client", // Verify audience
        clockTolerance: 0, // No clock tolerance (strict timing)
      }) as unknown as JwtPayload;

      // Validate required claims
      if (!decoded.username || !decoded.email) {
        logger.error("JWT verify: Missing required claims (username/email)");
        return null;
      }

      // Validate jti exists (every token must be unique)
      if (!decoded.jti) {
        logger.error("JWT verify: Missing jti claim");
        return null;
      }

      return decoded;
    } catch (error: any) {
      // Log specific JWT errors (but don't expose to client)
      if (error.name === "TokenExpiredError") {
        logger.warn("JWT verify: Token expired");
      } else if (error.name === "JsonWebTokenError") {
        logger.warn("JWT verify: Invalid token", { error: error.message });
      } else if (error.name === "NotBeforeError") {
        logger.warn("JWT verify: Token not yet valid");
      } else {
        logger.error("JWT verify: Unexpected error", { error: error.message });
      }

      return null;
    }
  }

  /**
   * Декодирование без проверки (ТОЛЬКО для debug/logging)
   * NEVER use this for authentication!
   */
  static decode(token: string): JwtPayload | null {
    try {
      const decoded = jwt.decode(token) as JwtPayload;

      // Even in decode, validate structure
      if (!decoded || !decoded.username || !decoded.email) {
        return null;
      }

      return decoded;
    } catch (error) {
      logger.error("JWT decode error", { error });
      return null;
    }
  }

  /**
   * Check if token is expired (without full verification)
   */
  static isExpired(token: string): boolean {
    try {
      const decoded = jwt.decode(token) as JwtPayload;
      if (!decoded || !decoded.exp) {
        return true;
      }

      // Check if expired
      return decoded.exp < Date.now() / 1000;
    } catch (error) {
      return true;
    }
  }
}
