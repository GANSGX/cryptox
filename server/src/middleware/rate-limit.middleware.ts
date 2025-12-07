/**
 * 🛡️ PER-ENDPOINT RATE LIMITING
 *
 * Stricter rate limits for sensitive endpoints
 * DISABLED in tests to prevent cache issues
 */

import type { RateLimitOptions } from "@fastify/rate-limit";

// In tests, use very high limits to effectively disable rate limiting
// (can't use undefined because route config requires RateLimitOptions)
const TEST_MAX = process.env.NODE_ENV === "test" ? 999999 : undefined;

/**
 * Rate limit for login endpoint
 * 5 attempts per hour per IP (disabled in tests)
 */
export const loginRateLimit: RateLimitOptions = {
  max: TEST_MAX ?? 5,
  timeWindow: "1 hour",
  skipOnError: false,
  errorResponseBuilder: (request, context) => ({
    success: false,
    error: "Too many login attempts. Please try again in 1 hour.",
    retryAfter: context.after,
  }),
};

/**
 * Rate limit for register endpoint
 * 3 registrations per day per IP (disabled in tests)
 */
export const registerRateLimit: RateLimitOptions = {
  max: TEST_MAX ?? 3,
  timeWindow: "24 hours",
  skipOnError: false,
  errorResponseBuilder: (request, context) => ({
    success: false,
    error: "Too many registration attempts. Please try again tomorrow.",
    retryAfter: context.after,
  }),
};

/**
 * Rate limit for password reset
 * 5 attempts per hour per email (disabled in tests)
 */
export const passwordResetRateLimit: RateLimitOptions = {
  max: TEST_MAX ?? 5,
  timeWindow: "1 hour",
  skipOnError: false,
  errorResponseBuilder: (request, context) => ({
    success: false,
    error: "Too many password reset attempts. Please try again in 1 hour.",
    retryAfter: context.after,
  }),
};

/**
 * Rate limit for email verification code
 * 10 attempts per hour (disabled in tests)
 */
export const emailVerificationRateLimit: RateLimitOptions = {
  max: TEST_MAX ?? 10,
  timeWindow: "1 hour",
  skipOnError: false,
  errorResponseBuilder: (request, context) => ({
    success: false,
    error: "Too many verification attempts. Please try again later.",
    retryAfter: context.after,
  }),
};
