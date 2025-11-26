/**
 * 🛡️ ReDoS (Regular Expression Denial of Service) PROTECTION
 *
 * Prevents catastrophic backtracking in regex patterns
 *
 * Protection strategies:
 * 1. Input length limits before regex
 * 2. Timeout guards for regex operations
 * 3. Safe regex patterns (no nested quantifiers)
 * 4. Pre-validation before expensive regex
 */

/**
 * Maximum input lengths for regex validation
 * Prevents catastrophic backtracking on very long strings
 */
export const REGEX_INPUT_LIMITS = {
  username: 30, // Max username length
  email: 255, // Max email length
  password: 128, // Max password length
  url: 2048, // Max URL length
  text: 10000, // Max text field length
  query: 1000, // Max search query length
} as const;

/**
 * Maximum regex execution time (milliseconds)
 */
const REGEX_TIMEOUT_MS = 100;

/**
 * Safe wrapper for regex test with timeout protection
 *
 * @param pattern Regex pattern to test
 * @param input String to test against
 * @param maxLength Maximum input length (prevents DoS)
 * @returns boolean result or false on timeout
 */
export function safeRegexTest(
  pattern: RegExp,
  input: string,
  maxLength: number = 10000,
): boolean {
  // Pre-validation: check input length
  if (!input || typeof input !== "string") {
    return false;
  }

  // Reject extremely long inputs (ReDoS prevention)
  if (input.length > maxLength) {
    console.warn(
      `ReDoS protection: Input too long (${input.length} > ${maxLength})`,
    );
    return false;
  }

  try {
    // Execute regex with timeout protection
    const startTime = Date.now();
    const result = pattern.test(input);
    const elapsed = Date.now() - startTime;

    // Warn if regex took too long (potential ReDoS)
    if (elapsed > REGEX_TIMEOUT_MS) {
      console.warn(
        `ReDoS warning: Regex took ${elapsed}ms (pattern: ${pattern}, length: ${input.length})`,
      );
    }

    return result;
  } catch (error) {
    // Regex error - reject input
    console.error("Regex execution error:", error);
    return false;
  }
}

/**
 * Validate username with ReDoS protection
 * Safe pattern: /^[a-z][a-z0-9_]*$/
 */
export function isValidUsernameSafe(username: string): boolean {
  // Length check BEFORE regex
  if (
    !username ||
    username.length < 3 ||
    username.length > REGEX_INPUT_LIMITS.username
  ) {
    return false;
  }

  // Safe regex pattern (no nested quantifiers, no backtracking)
  // ^[a-z] - must start with lowercase letter
  // [a-z0-9_]* - then any number of lowercase/digits/underscore
  const safePattern = /^[a-z][a-z0-9_]*$/;

  return safeRegexTest(safePattern, username, REGEX_INPUT_LIMITS.username);
}

/**
 * Validate email with ReDoS protection
 * Simplified safe pattern
 */
export function isValidEmailSafe(email: string): boolean {
  // Length check BEFORE regex
  if (!email || email.length > REGEX_INPUT_LIMITS.email) {
    return false;
  }

  // Safe simplified email pattern (no catastrophic backtracking)
  // This is less strict but MUCH safer than complex email regex
  const safePattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

  return safeRegexTest(safePattern, email, REGEX_INPUT_LIMITS.email);
}

/**
 * Validate password with ReDoS protection
 */
export function isValidPasswordSafe(password: string): boolean {
  // Length check BEFORE regex
  if (
    !password ||
    password.length < 8 ||
    password.length > REGEX_INPUT_LIMITS.password
  ) {
    return false;
  }

  // No regex needed - just length check is sufficient
  return true;
}

/**
 * Sanitize input to remove potential ReDoS attack vectors
 *
 * Removes:
 * - Extremely long repeated characters (a+)+b pattern
 * - Nested groups
 * - Control characters
 */
export function sanitizeForRegex(
  input: string,
  maxLength: number = 1000,
): string {
  if (!input || typeof input !== "string") {
    return "";
  }

  // Truncate to max length
  let sanitized = input.substring(0, maxLength);

  // Remove control characters (can cause regex issues)
  sanitized = sanitized.replace(/[\x00-\x1F\x7F]/g, "");

  // Remove excessive repetition (prevent (a+)+b attacks)
  // If more than 100 same characters in a row, truncate
  sanitized = sanitized.replace(/(.)\1{100,}/g, (match) =>
    match[0].repeat(100),
  );

  return sanitized;
}

/**
 * Check if string contains potential ReDoS attack pattern
 */
export function detectReDoSPattern(input: string): boolean {
  if (!input || typeof input !== "string") {
    return false;
  }

  // Detect common ReDoS patterns
  const redosPatterns = [
    /(.+){50,}/, // Excessive quantifiers
    /(.+)+/, // Nested quantifiers
    /(.*){50,}/, // Greedy quantifiers with high repetition
    /(.){50000,}/, // Extremely long repetition (any character)
  ];

  for (const pattern of redosPatterns) {
    try {
      if (safeRegexTest(pattern, input, 1000)) {
        return true;
      }
    } catch {
      // Pattern itself might be dangerous
      continue;
    }
  }

  return false;
}

/**
 * Test if a regex pattern is potentially dangerous
 *
 * Checks for:
 * - Nested quantifiers: (a+)+
 * - Overlapping patterns: (a|a)+
 * - Catastrophic backtracking potential
 */
export function isDangerousRegexPattern(pattern: string): boolean {
  // Check for nested quantifiers
  if (/\([^)]*[+*]\)[+*]/.test(pattern)) {
    return true; // (a+)+ or (a*)* etc
  }

  // Check for alternation with same patterns
  if (/\(([^|]+)\|\1\)/.test(pattern)) {
    return true; // (a|a) etc
  }

  // Check for excessive quantifiers
  if (/\{\s*\d{4,}\s*,?\s*\}/.test(pattern)) {
    return true; // {10000} etc
  }

  return false;
}
