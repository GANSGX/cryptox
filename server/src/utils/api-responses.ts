/**
 * 🛡️ SECURE API RESPONSE UTILITIES
 *
 * Centralized response helpers that prevent information disclosure
 *
 * Key principles:
 * - Generic error messages (no details about what exists/doesn't exist)
 * - No stack traces
 * - No internal paths or schema details
 * - Consistent response format
 */

import type { FastifyReply } from "fastify";

/**
 * Generic error responses to prevent information disclosure
 */
const GENERIC_ERRORS = {
  // Auth errors (don't reveal if user/email exists)
  INVALID_CREDENTIALS: "Invalid credentials",
  AUTH_REQUIRED: "Authentication required",
  ACCESS_DENIED: "Access denied",
  ACCOUNT_DISABLED: "Account is disabled",

  // Validation errors (generic)
  INVALID_REQUEST: "Invalid request",
  MISSING_FIELDS: "Missing required fields",
  INVALID_FORMAT: "Invalid format",

  // Resource errors (don't reveal existence)
  NOT_FOUND: "Resource not found",
  ALREADY_EXISTS: "Resource already exists",

  // Rate limiting
  TOO_MANY_REQUESTS: "Too many requests. Please try again later.",

  // Generic fallback
  INTERNAL_ERROR: "Internal server error",
  SERVICE_UNAVAILABLE: "Service temporarily unavailable",
} as const;

/**
 * Success response helper
 */
export function sendSuccess(
  reply: FastifyReply,
  data?: any,
  statusCode: number = 200,
) {
  return reply.code(statusCode).send({
    success: true,
    ...(data && { data }),
  });
}

/**
 * Error response helper (prevents information disclosure)
 */
export function sendError(
  reply: FastifyReply,
  errorType: keyof typeof GENERIC_ERRORS,
  statusCode: number = 400,
  additionalData?: Record<string, any>,
) {
  return reply.code(statusCode).send({
    success: false,
    error: GENERIC_ERRORS[errorType],
    ...additionalData,
  });
}

/**
 * Authentication errors (401)
 * Use these for login/registration to prevent username/email enumeration
 */
export function sendAuthError(
  reply: FastifyReply,
  type: "INVALID_CREDENTIALS" | "AUTH_REQUIRED" = "INVALID_CREDENTIALS",
) {
  return sendError(reply, type, 401);
}

/**
 * Authorization errors (403)
 */
export function sendForbiddenError(reply: FastifyReply) {
  return sendError(reply, "ACCESS_DENIED", 403);
}

/**
 * Not found errors (404)
 * Generic message that doesn't reveal if resource exists
 */
export function sendNotFoundError(reply: FastifyReply) {
  return sendError(reply, "NOT_FOUND", 404);
}

/**
 * Conflict errors (409)
 * Generic message that doesn't reveal what exists
 */
export function sendConflictError(reply: FastifyReply) {
  return sendError(reply, "ALREADY_EXISTS", 409);
}

/**
 * Validation errors (400)
 */
export function sendValidationError(
  reply: FastifyReply,
  details?: Array<{ field: string; message: string }>,
) {
  return sendError(reply, "INVALID_REQUEST", 400, {
    ...(details && { details }),
  });
}

/**
 * Rate limit errors (429)
 */
export function sendRateLimitError(reply: FastifyReply, retryAfter?: number) {
  return sendError(reply, "TOO_MANY_REQUESTS", 429, {
    ...(retryAfter && { retryAfter }),
  });
}

/**
 * Internal server errors (500)
 * NEVER include error details in production
 */
export function sendInternalError(reply: FastifyReply) {
  return sendError(reply, "INTERNAL_ERROR", 500);
}

/**
 * Service unavailable errors (503)
 */
export function sendServiceUnavailableError(reply: FastifyReply) {
  return sendError(reply, "SERVICE_UNAVAILABLE", 503);
}

/**
 * Wrap try-catch block with automatic error handling
 * Prevents accidental error detail leaks
 */
export async function safeHandler(
  fn: () => Promise<any>,
  reply: FastifyReply,
): Promise<void> {
  try {
    await fn();
  } catch (error) {
    // Log error server-side (not sent to client)
    console.error("Handler error:", error);

    // Send generic error to client
    sendInternalError(reply);
  }
}
