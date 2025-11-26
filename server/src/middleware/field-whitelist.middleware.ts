/**
 * 🛡️ FIELD WHITELISTING MIDDLEWARE
 *
 * Protection against Mass Assignment vulnerabilities
 *
 * Prevents attackers from setting protected fields like:
 * - is_admin
 * - is_banned
 * - email_verified
 * - role
 * - permissions
 */

import type { FastifyRequest, FastifyReply } from "fastify";

/**
 * Whitelist allowed fields in request body
 * Removes any fields not in the whitelist
 */
export function whitelistFields(allowedFields: string[]) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    if (!request.body || typeof request.body !== "object") {
      return;
    }

    const body = request.body as Record<string, any>;
    const filteredBody: Record<string, any> = {};

    // Only keep allowed fields
    for (const field of allowedFields) {
      if (field in body) {
        filteredBody[field] = body[field];
      }
    }

    // Replace body with filtered version
    request.body = filteredBody;
  };
}

/**
 * Blacklist protected fields
 * Removes dangerous fields that should NEVER be set by users
 */
export async function blacklistProtectedFields(
  request: FastifyRequest,
  reply: FastifyReply,
) {
  if (!request.body || typeof request.body !== "object") {
    return;
  }

  const body = request.body as Record<string, any>;

  // Protected fields that should NEVER be set via API
  const protectedFields = [
    "is_admin",
    "is_banned",
    "email_verified",
    "role",
    "permissions",
    "spam_score",
    "created_at",
    "updated_at",
    "id",
    "__proto__",
    "constructor",
    "prototype",
  ];

  // Remove protected fields
  for (const field of protectedFields) {
    if (field in body) {
      delete body[field];
    }
  }

  // Check for nested __proto__ pollution
  if (Object.prototype.hasOwnProperty.call(body, "__proto__")) {
    delete body.__proto__;
  }

  // Check for constructor pollution - safely remove if it's not the built-in
  const bodyAny = body as any;
  if (
    Object.prototype.hasOwnProperty.call(body, "constructor") &&
    typeof bodyAny.constructor !== "function"
  ) {
    delete bodyAny.constructor;
  }

  request.body = body;
}

/**
 * Validate that user can only modify their own resources
 * Prevents IDOR (Insecure Direct Object Reference)
 */
export function ensureOwnership(usernameField: string = "username") {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    // Get authenticated user from request
    const authUser = (request as any).user;

    if (!authUser || !authUser.username) {
      return reply.code(401).send({
        success: false,
        error: "Unauthorized",
      });
    }

    // Check if request tries to access another user's resource
    const targetUsername =
      (request.body as any)?.[usernameField] ||
      (request.params as any)?.[usernameField] ||
      (request.query as any)?.[usernameField];

    if (targetUsername && targetUsername !== authUser.username) {
      return reply.code(403).send({
        success: false,
        error: "Access denied",
      });
    }
  };
}

/**
 * Sanitize user object before sending to client
 * Removes sensitive fields
 */
export function sanitizeUserObject(user: any): any {
  if (!user) return null;

  // Remove sensitive fields
  const {
    salt,
    auth_token,
    encrypted_master_key,
    password,
    password_key,
    ...sanitized
  } = user;

  return sanitized;
}

/**
 * Sanitize array of users
 */
export function sanitizeUserArray(users: any[]): any[] {
  return users.map(sanitizeUserObject);
}
