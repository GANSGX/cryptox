/**
 * 🛡️ TIMING-SAFE STRING COMPARISON
 *
 * Prevents timing attacks by ensuring comparison takes constant time
 * regardless of where strings differ.
 *
 * Use this for comparing:
 * - Passwords
 * - JWT tokens
 * - Reset tokens
 * - API keys
 * - Session IDs
 * - Any secret values
 *
 * DO NOT use === or == for secrets!
 */

import { timingSafeEqual } from "crypto";

/**
 * Compare two strings in constant time
 * Prevents timing attacks
 */
export function timingSafeStringCompare(a: string, b: string): boolean {
  // If lengths differ, still do comparison to prevent timing leak
  // Pad shorter string with zeros to match length
  const maxLength = Math.max(a.length, b.length);
  const bufferA = Buffer.alloc(maxLength);
  const bufferB = Buffer.alloc(maxLength);

  bufferA.write(a);
  bufferB.write(b);

  // timingSafeEqual from crypto module ensures constant-time comparison
  try {
    return timingSafeEqual(bufferA, bufferB);
  } catch {
    // Buffers have different length (shouldn't happen due to alloc, but safety)
    return false;
  }
}

/**
 * Compare two Buffer objects in constant time
 */
export function timingSafeBufferCompare(a: Buffer, b: Buffer): boolean {
  // If lengths differ, pad to prevent timing leak
  if (a.length !== b.length) {
    const maxLength = Math.max(a.length, b.length);
    const paddedA = Buffer.alloc(maxLength);
    const paddedB = Buffer.alloc(maxLength);
    a.copy(paddedA);
    b.copy(paddedB);
    return timingSafeEqual(paddedA, paddedB);
  }

  return timingSafeEqual(a, b);
}
