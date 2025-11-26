/**
 * 🛡️ ENHANCED ERROR HANDLER
 *
 * Secure error handling that prevents information disclosure:
 * - NO stack traces in production
 * - NO internal paths
 * - NO database schema details
 * - NO sensitive data
 * - Generic error messages for security
 */

import type { FastifyError, FastifyRequest, FastifyReply } from "fastify";
import { logger } from "../services/logger.service.js";

/**
 * Check if we're in production
 */
function isProduction(): boolean {
  return process.env.NODE_ENV === "production";
}

/**
 * Sanitize error message for public display
 * Removes all sensitive information
 */
function sanitizeErrorMessage(message: string): string {
  // Remove file paths
  message = message.replace(/\/[^\s]+/g, "[path]");
  message = message.replace(/C:\\[^\s]+/g, "[path]");

  // Remove SQL table/column names
  message = message.replace(/table\s+"[^"]+"/gi, "table [redacted]");
  message = message.replace(/column\s+"[^"]+"/gi, "column [redacted]");

  // Remove stack trace references
  message = message.replace(/at\s+\w+\s+\([^)]+\)/g, "");

  // Remove internal error codes
  message = message.replace(/Error:\s+\w+Error:/g, "Error:");

  return message.trim();
}

/**
 * Get generic error message based on status code
 */
function getGenericErrorMessage(statusCode: number): string {
  const messages: Record<number, string> = {
    400: "Invalid request",
    401: "Authentication required",
    403: "Access denied",
    404: "Resource not found",
    409: "Resource already exists",
    413: "Request too large",
    429: "Too many requests",
    500: "Internal server error",
    502: "Bad gateway",
    503: "Service unavailable",
  };

  return messages[statusCode] || "An error occurred";
}

/**
 * Enhanced error handler middleware
 */
export async function enhancedErrorHandler(
  error: FastifyError,
  request: FastifyRequest,
  reply: FastifyReply,
) {
  const isProd = isProduction();

  // Log full error details (server-side only)
  logger.error("Request error:", {
    error: {
      name: error.name,
      message: error.message,
      stack: error.stack,
      statusCode: error.statusCode,
    },
    request: {
      method: request.method,
      url: request.url,
      ip: request.ip,
      headers: {
        "user-agent": request.headers["user-agent"],
        referer: request.headers["referer"],
      },
      // DO NOT log body (may contain passwords/tokens)
    },
  });

  // Determine status code
  const statusCode = error.statusCode || 500;

  // Check if error should be hidden (security-sensitive)
  const isSecurityError =
    error.message?.toLowerCase().includes("sql") ||
    error.message?.toLowerCase().includes("database") ||
    error.message?.toLowerCase().includes("redis") ||
    error.message?.toLowerCase().includes("jwt") ||
    error.message?.toLowerCase().includes("token") ||
    error.message?.toLowerCase().includes("crypto") ||
    error.message?.toLowerCase().includes("argon") ||
    error.message?.toLowerCase().includes("password") ||
    statusCode === 500;

  // Prepare response
  const response: any = {
    success: false,
    error: "",
  };

  if (isProd || isSecurityError) {
    // Production or security-sensitive: generic message
    response.error = getGenericErrorMessage(statusCode);

    // Add error ID for support/debugging
    response.errorId = `ERR-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  } else {
    // Development: sanitized message
    response.error = sanitizeErrorMessage(error.message || "Unknown error");

    // Add validation errors if present
    if (error.validation) {
      response.validation = error.validation;
    }
  }

  // NEVER include in response (security):
  // - stack traces
  // - internal paths
  // - database schema
  // - SQL queries
  // - environment variables
  // - server configuration

  // Send response
  reply.code(statusCode).send(response);
}

/**
 * Handle uncaught exceptions
 */
export function handleUncaughtException(error: Error) {
  logger.error("Uncaught exception:", {
    error: {
      name: error.name,
      message: error.message,
      stack: error.stack,
    },
  });

  // In production, keep server running
  // In development, crash to make errors obvious
  if (!isProduction()) {
    process.exit(1);
  }
}

/**
 * Handle unhandled promise rejections
 */
export function handleUnhandledRejection(reason: any, promise: Promise<any>) {
  logger.error("Unhandled promise rejection:", {
    reason,
    promise,
  });

  // In production, keep server running
  // In development, crash to make errors obvious
  if (!isProduction()) {
    process.exit(1);
  }
}

/**
 * Validation error handler (for Zod errors)
 */
export function handleValidationError(
  error: any,
  request: FastifyRequest,
  reply: FastifyReply,
) {
  // Log validation error
  logger.warn("Validation error:", {
    url: request.url,
    method: request.method,
    error: error.message,
    issues: error.issues,
  });

  // Send sanitized validation errors
  reply.code(400).send({
    success: false,
    error: "Validation failed",
    details: error.issues?.map((issue: any) => ({
      field: issue.path?.join("."),
      message: sanitizeErrorMessage(issue.message),
    })),
  });
}

/**
 * Rate limit error handler
 */
export function handleRateLimitError(
  request: FastifyRequest,
  reply: FastifyReply,
  retryAfter: number,
) {
  logger.warn("Rate limit exceeded:", {
    ip: request.ip,
    url: request.url,
    retryAfter,
  });

  reply.code(429).send({
    success: false,
    error: "Too many requests",
    retryAfter,
  });
}

/**
 * Setup global error handlers
 */
export function setupGlobalErrorHandlers() {
  // Uncaught exceptions
  process.on("uncaughtException", handleUncaughtException);

  // Unhandled promise rejections
  process.on("unhandledRejection", handleUnhandledRejection);

  // Graceful shutdown on SIGTERM
  process.on("SIGTERM", () => {
    logger.info("SIGTERM received, shutting down gracefully");
    process.exit(0);
  });

  // Graceful shutdown on SIGINT (Ctrl+C)
  process.on("SIGINT", () => {
    logger.info("SIGINT received, shutting down gracefully");
    process.exit(0);
  });
}
