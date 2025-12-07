/**
 * 🛡️ AUTHENTICATION VALIDATION SCHEMAS
 *
 * Strict validation schemas using Zod
 * Prevents ALL injection attacks at schema level
 * + ReDoS protection with input length limits
 */

import { z } from "zod";
import {
  REGEX_INPUT_LIMITS,
  sanitizeForRegex,
} from "../utils/redos-protection.js";

// ============================================================================
// USERNAME VALIDATION
// ============================================================================

/**
 * Username rules:
 * - 3-30 characters
 * - Only lowercase letters, numbers, underscore
 * - Must start with letter
 * - No SQL/XSS/Command injection characters
 */
export const usernameSchema = z
  .string()
  .toLowerCase() // Auto-normalize to lowercase (DB constraint requires it anyway)
  .min(3, "Username must be at least 3 characters")
  .max(REGEX_INPUT_LIMITS.username, "Username too long") // ReDoS: REJECT long inputs BEFORE processing
  .refine(
    (val) => {
      // Safe regex pattern (no nested quantifiers)
      // Length already checked by .max() above
      return /^[a-z][a-z0-9_]*$/.test(val);
    },
    {
      message:
        "Username must start with letter and contain only lowercase letters, numbers, and underscore",
    },
  )
  .refine(
    (val) => {
      // Block SQL injection patterns
      const sqlPatterns = [
        /--/,
        /;/,
        /'/,
        /"/,
        /\\/,
        /\bor\b/i,
        /\band\b/i,
        /\bselect\b/i,
        /\bdrop\b/i,
        /\bunion\b/i,
      ];
      return !sqlPatterns.some((pattern) => pattern.test(val));
    },
    { message: "Username contains invalid characters" },
  )
  .refine(
    (val) => {
      // Block XSS patterns
      const xssPatterns = [/</, />/, /javascript:/i, /on\w+=/i];
      return !xssPatterns.some((pattern) => pattern.test(val));
    },
    { message: "Username contains invalid characters" },
  )
  .refine(
    (val) => {
      // Block command injection
      const cmdPatterns = [/[;&|`$()<>]/];
      return !cmdPatterns.some((pattern) => pattern.test(val));
    },
    { message: "Username contains invalid characters" },
  );

// ============================================================================
// EMAIL VALIDATION
// ============================================================================

/**
 * Email validation with security checks
 */
export const emailSchema = z
  .string()
  .max(REGEX_INPUT_LIMITS.email, "Email too long") // ReDoS: REJECT long inputs BEFORE processing
  .toLowerCase()
  .refine(
    (val) => {
      // Simplified safe email pattern (no catastrophic backtracking)
      // Length already checked by .max() above
      return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(val);
    },
    { message: "Invalid email format" },
  )
  .refine(
    (val) => {
      // Block unusual characters that might be used in injection
      const suspiciousPatterns = [
        /[<>]/, // HTML tags
        /[;|&`$()]/, // Command injection
        /\r|\n/, // CRLF injection
      ];
      return !suspiciousPatterns.some((pattern) => pattern.test(val));
    },
    { message: "Email contains invalid characters" },
  )
  .refine(
    (val) => {
      // Validate domain part
      const parts = val.split("@");
      if (parts.length !== 2) return false;
      const domain = parts[1];

      // Block internal/localhost domains (SSRF protection)
      const blockedDomains = [
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "169.254.169.254", // AWS metadata
        "metadata.google.internal", // GCP metadata
      ];

      return !blockedDomains.some((blocked) => domain.includes(blocked));
    },
    { message: "Email domain not allowed" },
  );

// ============================================================================
// PASSWORD VALIDATION
// ============================================================================

/**
 * Password validation
 * - Minimum 8 characters (12+ recommended in docs)
 * - No maximum to allow strong passwords
 */
export const passwordSchema = z
  .string()
  .min(8, "Password must be at least 8 characters")
  .max(REGEX_INPUT_LIMITS.password, "Password too long") // ReDoS: strict length limit
  .refine(
    (val) => {
      // Password can contain any characters (it will be hashed)
      // But check for null bytes (can cause issues)
      return !val.includes("\0");
    },
    { message: "Password contains invalid characters" },
  );

// ============================================================================
// PUBLIC KEY VALIDATION
// ============================================================================

/**
 * Public key validation (hex string, 64 chars = 32 bytes)
 */
export const publicKeySchema = z
  .string()
  .length(64, "Public key must be 64 hex characters")
  .regex(/^[a-f0-9]{64}$/, "Public key must be hex string");

// ============================================================================
// DEVICE FINGERPRINT VALIDATION
// ============================================================================

/**
 * Device fingerprint validation
 */
export const deviceFingerprintSchema = z
  .string()
  .min(10, "Device fingerprint too short")
  .max(200, "Device fingerprint too long")
  .regex(/^[a-zA-Z0-9_-]+$/, "Invalid device fingerprint format");

// ============================================================================
// ENCRYPTED DATA VALIDATION
// ============================================================================

/**
 * Encrypted master key validation
 */
export const encryptedMasterKeySchema = z
  .string()
  .min(50, "Encrypted master key too short")
  .max(500, "Encrypted master key too long")
  .regex(/^[a-f0-9]+$/, "Encrypted master key must be hex string");

// ============================================================================
// VERIFICATION CODE VALIDATION
// ============================================================================

/**
 * 6-digit verification code
 */
export const verificationCodeSchema = z
  .string()
  .length(6, "Verification code must be 6 digits")
  .regex(/^\d{6}$/, "Verification code must contain only digits");

// ============================================================================
// REGISTER REQUEST SCHEMA
// ============================================================================

export const registerSchema = z.object({
  username: usernameSchema,
  email: emailSchema,
  password: passwordSchema,
  public_key: publicKeySchema,
  deviceFingerprint: deviceFingerprintSchema.optional(),
});

export type RegisterInput = z.infer<typeof registerSchema>;

// ============================================================================
// LOGIN REQUEST SCHEMA
// ============================================================================

export const loginSchema = z.object({
  username: usernameSchema,
  password: passwordSchema,
  deviceFingerprint: deviceFingerprintSchema.optional(),
});

export type LoginInput = z.infer<typeof loginSchema>;

// ============================================================================
// VERIFY EMAIL SCHEMA
// ============================================================================

export const verifyEmailSchema = z.object({
  code: verificationCodeSchema,
});

export type VerifyEmailInput = z.infer<typeof verifyEmailSchema>;

// ============================================================================
// SEND VERIFICATION CODE SCHEMA
// ============================================================================

export const sendVerificationCodeSchema = z.object({
  email: emailSchema.optional(),
});

export type SendVerificationCodeInput = z.infer<
  typeof sendVerificationCodeSchema
>;

// ============================================================================
// RESET PASSWORD SCHEMA
// ============================================================================

export const resetPasswordInitSchema = z.object({
  email: emailSchema,
});

export type ResetPasswordInitInput = z.infer<typeof resetPasswordInitSchema>;

export const resetPasswordCompleteSchema = z.object({
  email: emailSchema,
  code: verificationCodeSchema,
  new_password: passwordSchema,
  encrypted_master_key: encryptedMasterKeySchema,
});

export type ResetPasswordCompleteInput = z.infer<
  typeof resetPasswordCompleteSchema
>;

// ============================================================================
// CHANGE EMAIL SCHEMA
// ============================================================================

export const changeEmailSchema = z.object({
  new_email: emailSchema,
  code: verificationCodeSchema,
});

export type ChangeEmailInput = z.infer<typeof changeEmailSchema>;

// ============================================================================
// CHANGE PASSWORD SCHEMA
// ============================================================================

export const changePasswordSchema = z.object({
  current_password: passwordSchema,
  new_password: passwordSchema,
  encrypted_master_key: encryptedMasterKeySchema,
});

export type ChangePasswordInput = z.infer<typeof changePasswordSchema>;

// ============================================================================
// DEVICE APPROVAL SCHEMA
// ============================================================================

export const approveDeviceSchema = z.object({
  session_id: z.string().uuid("Invalid session ID"),
  approve: z.boolean(),
});

export type ApproveDeviceInput = z.infer<typeof approveDeviceSchema>;

export const verifyApprovalCodeSchema = z.object({
  code: verificationCodeSchema,
});

export type VerifyApprovalCodeInput = z.infer<typeof verifyApprovalCodeSchema>;
