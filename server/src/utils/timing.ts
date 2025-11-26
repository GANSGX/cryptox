/**
 * 🛡️ TIMING ATTACK PREVENTION
 *
 * Utilities to prevent timing attacks and username enumeration
 *
 * Protection against:
 * - Username enumeration via response time differences
 * - Password verification timing attacks
 * - Email existence checking via timing
 */

import crypto from "crypto";

/**
 * Constant-time delay to make responses uniform
 * Prevents timing-based username enumeration
 *
 * Usage: await constantTimeDelay(startTime, 300);
 */
export async function constantTimeDelay(
  startTime: number,
  minimumMs: number = 300,
): Promise<void> {
  const elapsed = Date.now() - startTime;
  const remaining = minimumMs - elapsed;

  if (remaining > 0) {
    await new Promise((resolve) => setTimeout(resolve, remaining));
  }
}

/**
 * Add random jitter to response time
 * Makes timing attacks even harder
 *
 * @param minMs Minimum milliseconds
 * @param maxMs Maximum milliseconds
 */
export async function randomJitter(
  minMs: number = 50,
  maxMs: number = 150,
): Promise<void> {
  const jitter = Math.random() * (maxMs - minMs) + minMs;
  await new Promise((resolve) => setTimeout(resolve, jitter));
}

/**
 * Fake password hash operation
 * Used when user doesn't exist to maintain constant time
 */
export async function fakePasswordHash(): Promise<void> {
  // Generate random salt and password
  const fakePassword = crypto.randomBytes(16).toString("hex");
  const fakeSalt = crypto.randomBytes(32).toString("hex");

  // Import argon2 dynamically to avoid circular dependency
  const argon2 = (await import("argon2")).default;

  // Perform fake hash (same time as real hash)
  await argon2.hash(fakePassword, {
    type: argon2.argon2id,
    memoryCost: 256 * 1024, // 256 MB
    timeCost: 4,
    parallelism: 4,
    salt: Buffer.from(fakeSalt.slice(0, 32)),
  });
}

/**
 * Generic error message for auth failures
 * Prevents information disclosure about whether user exists
 */
export const AUTH_ERROR_MESSAGE = "Invalid credentials";

/**
 * Generic error message for rate limiting
 * Doesn't reveal if user exists or not
 */
export const RATE_LIMIT_MESSAGE = "Too many attempts. Please try again later.";

/**
 * Constant-time string comparison
 * Prevents timing attacks on token comparison
 *
 * @param a First string
 * @param b Second string
 * @returns true if strings are equal
 */
export function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

/**
 * Wrapper for auth operations that ensures constant time
 * regardless of success or failure
 */
export async function withConstantTime<T>(
  operation: () => Promise<T>,
  minimumMs: number = 300,
): Promise<T> {
  const startTime = Date.now();

  try {
    const result = await operation();
    await constantTimeDelay(startTime, minimumMs);
    return result;
  } catch (error) {
    // Even on error, maintain constant time
    await constantTimeDelay(startTime, minimumMs);
    throw error;
  }
}
