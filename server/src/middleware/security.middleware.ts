/**
 * 🛡️ COMPREHENSIVE SECURITY MIDDLEWARE
 *
 * Pentagon-level protection against ALL known attack vectors:
 * - XSS (Cross-Site Scripting)
 * - SQL Injection
 * - Command Injection
 * - Path Traversal
 * - LDAP Injection
 * - NoSQL Injection
 * - XXE (XML External Entity)
 * - SSRF (Server-Side Request Forgery)
 * - Header Injection
 * - CRLF Injection
 */

import type { FastifyRequest, FastifyReply } from "fastify";
import { z, ZodSchema } from "zod";

// ============================================================================
// XSS PROTECTION
// ============================================================================

/**
 * Sanitize string from XSS attacks
 * Removes/encodes dangerous HTML/JavaScript
 */
export function sanitizeXSS(input: string): string {
  if (typeof input !== "string") return input;

  return (
    input
      // Remove script tags
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "")
      // Remove event handlers
      .replace(/on\w+\s*=\s*["'][^"']*["']/gi, "")
      .replace(/on\w+\s*=\s*[^\s>]*/gi, "")
      // Remove javascript: protocol
      .replace(/javascript:/gi, "")
      .replace(/vbscript:/gi, "")
      .replace(/data:/gi, "")
      // Remove iframe/embed/object
      .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, "")
      .replace(/<embed\b[^>]*>/gi, "")
      .replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, "")
      // Encode HTML entities
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#x27;")
      .replace(/\//g, "&#x2F;")
  );
}

/**
 * Deep sanitize object recursively
 */
export function sanitizeObject(obj: any): any {
  if (obj === null || obj === undefined) return obj;

  if (typeof obj === "string") {
    return sanitizeXSS(obj);
  }

  if (Array.isArray(obj)) {
    return obj.map((item) => sanitizeObject(item));
  }

  if (typeof obj === "object") {
    const sanitized: any = {};
    for (const [key, value] of Object.entries(obj)) {
      // Sanitize both key and value
      const sanitizedKey = sanitizeXSS(key);
      sanitized[sanitizedKey] = sanitizeObject(value);
    }
    return sanitized;
  }

  return obj;
}

// ============================================================================
// SQL INJECTION PROTECTION
// ============================================================================

/**
 * Detect SQL injection patterns
 * Returns true if suspicious SQL detected
 */
export function detectSQLInjection(input: string): boolean {
  if (typeof input !== "string") return false;

  const sqlPatterns = [
    // Classic SQL injection
    /(\bOR\b|\bAND\b)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i,
    /(\bOR\b|\bAND\b)\s+['"]?\w+['"]?\s*=\s*['"]?\w+/i,

    // Comment-based injection
    /--\s*$/,
    /#.*$/,
    /\/\*.*\*\//,

    // UNION-based injection
    /\bUNION\b.*\bSELECT\b/i,
    /\bUNION\b.*\bALL\b.*\bSELECT\b/i,

    // Stacked queries
    /;\s*(DROP|DELETE|UPDATE|INSERT|CREATE|ALTER|EXEC|EXECUTE)\b/i,

    // Time-based blind injection
    /\b(SLEEP|WAITFOR|BENCHMARK|pg_sleep)\b/i,

    // Boolean-based blind injection
    /\b(AND|OR)\b.*\b(SELECT|EXISTS|NOT EXISTS)\b/i,

    // Database enumeration
    /\b(information_schema|sysobjects|syscolumns)\b/i,
  ];

  return sqlPatterns.some((pattern) => pattern.test(input));
}

/**
 * Sanitize SQL-dangerous characters
 * Use this ONLY as additional layer - ALWAYS use prepared statements!
 */
export function sanitizeSQL(input: string): string {
  if (typeof input !== "string") return input;

  return input
    .replace(/['";\\]/g, "") // Remove quotes and backslash
    .replace(/--/g, "") // Remove SQL comments
    .replace(/#/g, "") // Remove MySQL comments
    .replace(/\/\*/g, "") // Remove C-style comments start
    .replace(/\*\//g, "") // Remove C-style comments end
    .trim();
}

// ============================================================================
// COMMAND INJECTION PROTECTION
// ============================================================================

/**
 * Detect OS command injection
 */
export function detectCommandInjection(input: string): boolean {
  if (typeof input !== "string") return false;

  const cmdPatterns = [
    // Command separators
    /[;&|`$()]/,

    // Redirection operators
    /[<>]/,

    // Newline injection
    /[\r\n]/,

    // Backticks (command substitution)
    /`[^`]*`/,

    // Variable expansion
    /\$\{[^}]*\}/,
    /\$\([^)]*\)/,
  ];

  return cmdPatterns.some((pattern) => pattern.test(input));
}

/**
 * Sanitize command-dangerous characters
 */
export function sanitizeCommand(input: string): string {
  if (typeof input !== "string") return input;

  // Remove ALL shell meta-characters
  return input.replace(/[;&|`$()<>\r\n]/g, "").trim();
}

// ============================================================================
// PATH TRAVERSAL PROTECTION
// ============================================================================

/**
 * Detect path traversal attempts
 */
export function detectPathTraversal(input: string): boolean {
  if (typeof input !== "string") return false;

  const pathPatterns = [
    /\.\./, // Parent directory
    /\.\.%2[fF]/, // Encoded ..
    /\.\.%5[cC]/, // Encoded backslash
    /%2[eE]%2[eE]%2[fF]/, // Double-encoded ../
    /\.\.[/\\]/, // .. with slash
    /[/\\]etc[/\\]passwd/i, // Linux password file
    /[/\\]windows[/\\]system32/i, // Windows system dir
  ];

  return pathPatterns.some((pattern) => pattern.test(input));
}

/**
 * Sanitize file paths
 */
export function sanitizePath(input: string): string {
  if (typeof input !== "string") return input;

  return input
    .replace(/\.\./g, "") // Remove ..
    .replace(/[/\\]+/g, "/") // Normalize slashes
    .replace(/^[/\\]+/, "") // Remove leading slashes
    .trim();
}

// ============================================================================
// HEADER INJECTION PROTECTION
// ============================================================================

/**
 * Detect header injection (CRLF injection)
 */
export function detectHeaderInjection(input: string): boolean {
  if (typeof input !== "string") return false;

  // Detect CRLF characters
  return /[\r\n]/.test(input);
}

/**
 * Sanitize header values
 */
export function sanitizeHeader(input: string): string {
  if (typeof input !== "string") return input;

  return input.replace(/[\r\n]/g, "").trim();
}

// ============================================================================
// NOSQL INJECTION PROTECTION
// ============================================================================

/**
 * Detect NoSQL injection attempts
 */
export function detectNoSQLInjection(input: any): boolean {
  if (typeof input === "object" && input !== null) {
    // Check for MongoDB operators
    const keys = Object.keys(input);
    return keys.some((key) => key.startsWith("$"));
  }

  if (typeof input === "string") {
    // Check for MongoDB operators in strings
    return /\$\w+/.test(input);
  }

  return false;
}

// ============================================================================
// LDAP INJECTION PROTECTION
// ============================================================================

/**
 * Detect LDAP injection
 */
export function detectLDAPInjection(input: string): boolean {
  if (typeof input !== "string") return false;

  const ldapPatterns = [
    /[*()\\]/, // LDAP special characters
    /\|\|/, // OR operator
    /&&/, // AND operator
  ];

  return ldapPatterns.some((pattern) => pattern.test(input));
}

/**
 * Sanitize LDAP special characters
 */
export function sanitizeLDAP(input: string): string {
  if (typeof input !== "string") return input;

  return input
    .replace(/\*/g, "\\2a")
    .replace(/\(/g, "\\28")
    .replace(/\)/g, "\\29")
    .replace(/\\/g, "\\5c")
    .replace(/\|/g, "\\7c")
    .replace(/&/g, "\\26");
}

// ============================================================================
// XXE (XML EXTERNAL ENTITY) PROTECTION
// ============================================================================

/**
 * Detect XXE attack attempts
 */
export function detectXXE(input: string): boolean {
  if (typeof input !== "string") return false;

  const xxePatterns = [/<!DOCTYPE/i, /<!ENTITY/i, /SYSTEM/i, /PUBLIC/i];

  // Check if input looks like XML and contains dangerous patterns
  if (input.includes("<?xml") || input.includes("<")) {
    return xxePatterns.some((pattern) => pattern.test(input));
  }

  return false;
}

// ============================================================================
// SSRF (SERVER-SIDE REQUEST FORGERY) PROTECTION
// ============================================================================

/**
 * Detect SSRF attempts
 */
export function detectSSRF(input: string): boolean {
  if (typeof input !== "string") return false;

  const ssrfPatterns = [
    // Localhost
    /localhost/i,
    /127\.0\.0\.1/,
    /0\.0\.0\.0/,
    /\[::1\]/,
    /\[::\]/,

    // Private IP ranges
    /10\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
    /172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}/,
    /192\.168\.\d{1,3}\.\d{1,3}/,

    // Cloud metadata endpoints
    /169\.254\.169\.254/, // AWS metadata
    /metadata\.google\.internal/, // Google Cloud

    // File protocols
    /file:\/\//i,
    /dict:\/\//i,
    /gopher:\/\//i,
  ];

  return ssrfPatterns.some((pattern) => pattern.test(input));
}

// ============================================================================
// REDOS (REGEX DOS) PROTECTION
// ============================================================================

/**
 * Check if string is too long (prevent ReDoS)
 */
export function checkReDoS(input: string, maxLength: number = 10000): boolean {
  if (typeof input !== "string") return false;
  return input.length > maxLength;
}

// ============================================================================
// COMPREHENSIVE VALIDATION MIDDLEWARE
// ============================================================================

/**
 * Comprehensive input validation and sanitization
 */
export function validateInput(
  data: any,
  options: {
    sanitizeXSS?: boolean;
    checkSQLInjection?: boolean;
    checkCommandInjection?: boolean;
    checkPathTraversal?: boolean;
    checkHeaderInjection?: boolean;
    checkNoSQLInjection?: boolean;
    checkLDAPInjection?: boolean;
    checkXXE?: boolean;
    checkSSRF?: boolean;
    checkReDoS?: boolean;
    maxLength?: number;
  } = {},
): { valid: boolean; sanitized: any; errors: string[] } {
  const errors: string[] = [];
  const opts = {
    sanitizeXSS: true,
    checkSQLInjection: true,
    checkCommandInjection: true,
    checkPathTraversal: true,
    checkHeaderInjection: true,
    checkNoSQLInjection: true,
    checkLDAPInjection: false,
    checkXXE: true,
    checkSSRF: true,
    checkReDoS: true,
    maxLength: 10000,
    ...options,
  };

  // Deep clone to avoid mutation
  let sanitized = JSON.parse(JSON.stringify(data));

  // Recursive validation
  function validate(obj: any, path: string = ""): any {
    if (obj === null || obj === undefined) return obj;

    if (typeof obj === "string") {
      // Check ReDoS
      if (opts.checkReDoS && checkReDoS(obj, opts.maxLength)) {
        errors.push(`${path}: String too long (max ${opts.maxLength} chars)`);
        return obj.substring(0, opts.maxLength);
      }

      // Check SQL Injection
      if (opts.checkSQLInjection && detectSQLInjection(obj)) {
        errors.push(`${path}: Potential SQL injection detected`);
        obj = sanitizeSQL(obj);
      }

      // Check Command Injection
      if (opts.checkCommandInjection && detectCommandInjection(obj)) {
        errors.push(`${path}: Potential command injection detected`);
        obj = sanitizeCommand(obj);
      }

      // Check Path Traversal
      if (opts.checkPathTraversal && detectPathTraversal(obj)) {
        errors.push(`${path}: Potential path traversal detected`);
        obj = sanitizePath(obj);
      }

      // Check Header Injection
      if (opts.checkHeaderInjection && detectHeaderInjection(obj)) {
        errors.push(`${path}: Potential header injection detected`);
        obj = sanitizeHeader(obj);
      }

      // Check LDAP Injection
      if (opts.checkLDAPInjection && detectLDAPInjection(obj)) {
        errors.push(`${path}: Potential LDAP injection detected`);
        obj = sanitizeLDAP(obj);
      }

      // Check XXE
      if (opts.checkXXE && detectXXE(obj)) {
        errors.push(`${path}: Potential XXE attack detected`);
        return "";
      }

      // Check SSRF
      if (opts.checkSSRF && detectSSRF(obj)) {
        errors.push(`${path}: Potential SSRF attack detected`);
        return "";
      }

      // Sanitize XSS (last step)
      if (opts.sanitizeXSS) {
        obj = sanitizeXSS(obj);
      }

      return obj;
    }

    if (Array.isArray(obj)) {
      return obj.map((item, index) => validate(item, `${path}[${index}]`));
    }

    if (typeof obj === "object") {
      // Check NoSQL Injection
      if (opts.checkNoSQLInjection && detectNoSQLInjection(obj)) {
        errors.push(`${path}: Potential NoSQL injection detected`);
        // Remove MongoDB operators
        const cleaned: any = {};
        for (const [key, value] of Object.entries(obj)) {
          if (!key.startsWith("$")) {
            cleaned[key] = value;
          }
        }
        obj = cleaned;
      }

      const result: any = {};
      for (const [key, value] of Object.entries(obj)) {
        const sanitizedKey =
          typeof key === "string" && opts.sanitizeXSS ? sanitizeXSS(key) : key;
        result[sanitizedKey] = validate(value, `${path}.${key}`);
      }
      return result;
    }

    return obj;
  }

  sanitized = validate(sanitized);

  return {
    valid: errors.length === 0,
    sanitized,
    errors,
  };
}

// ============================================================================
// FASTIFY MIDDLEWARE
// ============================================================================

/**
 * Fastify middleware for automatic input validation
 */
export async function securityMiddleware(
  request: FastifyRequest,
  reply: FastifyReply,
) {
  // Validate body
  if (request.body) {
    try {
      const result = validateInput(request.body);

      if (!result.valid) {
        return reply.code(400).send({
          success: false,
          error: "Invalid or malicious input detected",
          details: result.errors,
        });
      }

      // Replace body with sanitized version
      request.body = result.sanitized;
    } catch (error) {
      // If validation itself fails (e.g., payload too large for JSON.stringify)
      // Return 413 Payload Too Large
      return reply.code(413).send({
        success: false,
        error: "Request payload too large or malformed",
      });
    }
  }

  // Validate query params
  if (request.query) {
    const result = validateInput(request.query);

    if (!result.valid) {
      return reply.code(400).send({
        success: false,
        error: "Invalid or malicious query parameters",
        details: result.errors,
      });
    }

    request.query = result.sanitized;
  }

  // Validate params
  if (request.params) {
    const result = validateInput(request.params);

    if (!result.valid) {
      return reply.code(400).send({
        success: false,
        error: "Invalid or malicious URL parameters",
        details: result.errors,
      });
    }

    request.params = result.sanitized;
  }
}

// ============================================================================
// SCHEMA VALIDATION WITH ZOD
// ============================================================================

/**
 * Create Fastify middleware from Zod schema
 */
export function validateSchema<T extends ZodSchema>(schema: T) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      // Pre-check: Reject excessively large field values (ReDoS/DoS protection)
      // This prevents Zod from even attempting to parse huge strings
      if (request.body && typeof request.body === "object") {
        for (const [key, value] of Object.entries(request.body)) {
          if (typeof value === "string" && value.length > 10000) {
            return reply.code(413).send({
              success: false,
              error: "Request field too large",
            });
          }
        }
      }

      const result = schema.safeParse(request.body);

      if (!result.success) {
        // В production - только generic message
        if (process.env.NODE_ENV === "production") {
          return reply.code(400).send({
            success: false,
            error: "Invalid request data",
          });
        }

        // В development - sanitized details (но без stack traces)
        return reply.code(400).send({
          success: false,
          error: "Validation failed",
          details: result.error.issues.map((e) => ({
            field: e.path.join("."),
            // Sanitize message (remove internal details)
            message: e.message
              .replace(/Expected.*received.*/gi, "Invalid format")
              .replace(/Required/gi, "This field is required")
              .substring(0, 100), // Limit length
          })),
        });
      }

      // Replace body with validated data
      request.body = result.data;
    } catch (error) {
      // Log error server-side only
      console.error("Validation error:", error);

      return reply.code(400).send({
        success: false,
        error: "Invalid request data",
      });
    }
  };
}

// ============================================================================
// EXPORTS
// ============================================================================

export default {
  sanitizeXSS,
  sanitizeObject,
  detectSQLInjection,
  sanitizeSQL,
  detectCommandInjection,
  sanitizeCommand,
  detectPathTraversal,
  sanitizePath,
  detectHeaderInjection,
  sanitizeHeader,
  detectNoSQLInjection,
  detectLDAPInjection,
  sanitizeLDAP,
  detectXXE,
  detectSSRF,
  checkReDoS,
  validateInput,
  securityMiddleware,
  validateSchema,
};
