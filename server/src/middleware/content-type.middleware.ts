/**
 * 🛡️ CONTENT-TYPE VALIDATION MIDDLEWARE
 *
 * Protection against Content-Type confusion attacks
 *
 * Prevents:
 * - Accepting XML when expecting JSON
 * - Processing unintended content types
 * - Content-Type smuggling attacks
 */

import type { FastifyRequest, FastifyReply } from "fastify";

/**
 * Validate Content-Type header for POST/PUT/PATCH requests
 * Only allows application/json
 */
export async function validateContentType(
  request: FastifyRequest,
  reply: FastifyReply,
) {
  // Only validate for requests with body
  const methodsWithBody = ["POST", "PUT", "PATCH"];

  if (!methodsWithBody.includes(request.method)) {
    return;
  }

  const contentType = request.headers["content-type"];

  // Content-Type is required for requests with body
  if (!contentType) {
    return reply.code(400).send({
      success: false,
      error: "Content-Type header is required",
    });
  }

  // Only accept application/json (with optional charset)
  const isValidJson =
    contentType === "application/json" ||
    contentType.startsWith("application/json;");

  if (!isValidJson) {
    return reply.code(415).send({
      success: false,
      error: "Unsupported Media Type. Only application/json is accepted",
      received: contentType,
    });
  }
}

/**
 * Strict Content-Type validation - rejects anything except application/json
 */
export async function strictContentType(
  request: FastifyRequest,
  reply: FastifyReply,
) {
  const methodsWithBody = ["POST", "PUT", "PATCH"];

  if (!methodsWithBody.includes(request.method)) {
    return;
  }

  const contentType = request.headers["content-type"];

  // Reject if not exactly application/json
  if (contentType !== "application/json") {
    return reply.code(415).send({
      success: false,
      error:
        'Content-Type must be exactly "application/json" (no charset, no parameters)',
      received: contentType || "none",
    });
  }
}
