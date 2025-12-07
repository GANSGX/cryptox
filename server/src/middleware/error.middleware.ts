import type { FastifyError, FastifyReply, FastifyRequest } from "fastify";

/**
 * Глобальный обработчик ошибок
 */
export function errorHandler(
  error: FastifyError,
  request: FastifyRequest,
  reply: FastifyReply,
) {
  // Логируем ошибку
  request.log.error(
    {
      err: error,
      req: {
        method: request.method,
        url: request.url,
        params: request.params,
        query: request.query,
      },
    },
    "Request error",
  );

  // Определяем код ошибки
  const statusCode = error.statusCode || 500;

  // Валидационные ошибки (Fastify validation)
  if (error.validation) {
    return reply.code(400).send({
      success: false,
      error: "Validation error",
      details: error.validation,
    });
  }

  // JWT ошибки
  if (error.message.includes("jwt") || error.message.includes("token")) {
    return reply.code(401).send({
      success: false,
      error: "Invalid or expired token",
    });
  }

  // Database ошибки
  if (error.message.includes("duplicate key") || error.code === "23505") {
    return reply.code(409).send({
      success: false,
      error: "Resource already exists",
    });
  }

  // Rate limit ошибки (уже обрабатываются rate-limit plugin)
  if (statusCode === 429) {
    return reply.code(429).send({
      success: false,
      error: error.message || "Too many requests",
    });
  }

  // Production & Test: не показываем детали ошибок для безопасности
  if (
    process.env.NODE_ENV === "production" ||
    process.env.NODE_ENV === "test"
  ) {
    return reply.code(statusCode).send({
      success: false,
      error:
        statusCode >= 500
          ? "Internal server error"
          : error.message || "An error occurred",
    });
  }

  // Development только: показываем детали для отладки
  return reply.code(statusCode).send({
    success: false,
    error: error.message || "An error occurred",
    stack: error.stack,
    details: {
      code: error.code,
      statusCode: error.statusCode,
    },
  });
}

/**
 * Обработчик 404 (Not Found)
 */
export function notFoundHandler(request: FastifyRequest, reply: FastifyReply) {
  return reply.code(404).send({
    success: false,
    error: "Route not found",
    path: request.url,
  });
}
