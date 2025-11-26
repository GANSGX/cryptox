/**
 * 🛡️ PER-ENDPOINT RATE LIMITING
 *
 * Stricter rate limits for sensitive endpoints
 */

import type { RateLimitOptions } from "@fastify/rate-limit";

/**
 * Rate limit for login endpoint
 * 5 attempts per hour per IP
 */
export const loginRateLimit: RateLimitOptions = {
  max: 5,
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
 * 3 registrations per day per IP
 */
export const registerRateLimit: RateLimitOptions = {
  max: 3,
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
 * 5 attempts per hour per email
 */
export const passwordResetRateLimit: RateLimitOptions = {
  max: 5,
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
 * 10 attempts per hour
 */
export const emailVerificationRateLimit: RateLimitOptions = {
  max: 10,
  timeWindow: "1 hour",
  skipOnError: false,
  errorResponseBuilder: (request, context) => ({
    success: false,
    error: "Too many verification attempts. Please try again later.",
    retryAfter: context.after,
  }),
};
