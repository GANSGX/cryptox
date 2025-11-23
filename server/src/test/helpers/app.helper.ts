// Test helper для создания Fastify app для тестов
import Fastify, { FastifyInstance } from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import { authRoutes } from "../../routes/auth.routes.js";
import { protectedRoutes } from "../../routes/protected.routes.js";
import { usersRoutes } from "../../routes/users.routes.js";
import { messagesRoutes } from "../../routes/messages.routes.js";
import { sessionsRoutes } from "../../routes/sessions.routes.js";
import {
  errorHandler,
  notFoundHandler,
} from "../../middleware/error.middleware.js";

export async function buildApp(opts = {}): Promise<FastifyInstance> {
  const fastify = Fastify({
    logger: false, // Отключаем логи в тестах
    ignoreTrailingSlash: true,
    ...opts,
  });

  // CORS
  await fastify.register(cors, {
    origin: true, // В тестах разрешаем все origins
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization"],
  });

  // Security headers
  await fastify.register(helmet, {
    contentSecurityPolicy: false, // Отключаем в тестах для простоты
    crossOriginEmbedderPolicy: false,
  });

  // Rate limiting (более мягкий для тестов)
  await fastify.register(rateLimit, {
    max: 1000, // Увеличиваем лимит для тестов
    timeWindow: "1 minute",
    skipOnError: true,
  });

  // Routes
  await fastify.register(authRoutes, { prefix: "/api/auth" });
  await fastify.register(protectedRoutes, { prefix: "/api" });
  await fastify.register(usersRoutes, { prefix: "/api/users" });
  await fastify.register(messagesRoutes, { prefix: "/api" });
  await fastify.register(sessionsRoutes, { prefix: "/api" });

  // Error handlers
  fastify.setErrorHandler(errorHandler);
  fastify.setNotFoundHandler(notFoundHandler);

  // Health check
  fastify.get("/health", async () => {
    return { status: "ok", timestamp: new Date().toISOString() };
  });

  return fastify;
}
