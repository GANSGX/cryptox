/**
 * 🛡️ DATABASE ERROR HANDLER
 *
 * Prevents database error information disclosure
 *
 * Protection against:
 * - Schema/table/column names leaking
 * - Constraint names exposing DB structure
 * - PostgreSQL error codes revealing details
 * - Query details in error messages
 */

import { logger } from "../services/logger.service.js";

/**
 * Sanitize database error for safe client response
 */
export function sanitizeDbError(error: any): string {
  // Log full error server-side
  logger.error("Database error:", {
    message: error.message,
    code: error.code,
    detail: error.detail,
    constraint: error.constraint,
  });

  // Common PostgreSQL error codes
  const pgErrorMap: Record<string, string> = {
    "23505": "Resource already exists", // unique_violation
    "23503": "Invalid reference", // foreign_key_violation
    "23502": "Missing required data", // not_null_violation
    "23514": "Invalid data", // check_violation
    "42P01": "Resource not found", // undefined_table
    "42703": "Invalid request", // undefined_column
    "22001": "Data too long", // string_data_right_truncation
    "22003": "Value out of range", // numeric_value_out_of_range
    "57014": "Request timeout", // query_canceled
    "53300": "Service temporarily unavailable", // too_many_connections
  };

  // Return generic message based on error code
  if (error.code && pgErrorMap[error.code]) {
    return pgErrorMap[error.code];
  }

  // Default generic error
  return "Database operation failed";
}

/**
 * Wrap database operation with error handling
 */
export async function safeDbQuery<T>(
  operation: () => Promise<T>,
  errorMessage: string = "Operation failed",
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    // Log full error server-side
    logger.error("DB query failed:", {
      error: error instanceof Error ? error.message : error,
      stack: error instanceof Error ? error.stack : undefined,
    });

    // Throw sanitized error
    throw new Error(sanitizeDbError(error));
  }
}

/**
 * Check if error is a database error
 */
export function isDatabaseError(error: any): boolean {
  return (
    error.code !== undefined && // Has PostgreSQL error code
    (error.code.startsWith("23") || // Integrity constraint violation
      error.code.startsWith("42") || // Syntax/access error
      error.code.startsWith("22") || // Data exception
      error.code.startsWith("53") || // Insufficient resources
      error.code.startsWith("57")) // Operator intervention
  );
}
