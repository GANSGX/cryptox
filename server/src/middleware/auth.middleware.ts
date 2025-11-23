import type { FastifyRequest, FastifyReply } from "fastify";
import { JwtService } from "../services/jwt.service.js";
import { pool } from "../db/pool.js";

// Кэш последнего обновления last_active для каждого токена (debounce)
const lastActivityUpdate = new Map<string, number>();

// Очищаем старые записи из кэша каждые 5 минут
setInterval(
  () => {
    const now = Date.now();
    const fiveMinutes = 5 * 60 * 1000;

    for (const [token, timestamp] of lastActivityUpdate.entries()) {
      if (now - timestamp > fiveMinutes) {
        lastActivityUpdate.delete(token);
      }
    }

    if (lastActivityUpdate.size > 0) {
      console.log(
        `🧹 Cleaned up activity cache. Remaining entries: ${lastActivityUpdate.size}`,
      );
    }
  },
  5 * 60 * 1000,
);

// Расширяем тип FastifyRequest для добавления user
declare module "fastify" {
  interface FastifyRequest {
    user?: {
      username: string;
      email: string;
    };
  }
}

/**
 * Middleware для проверки JWT токена
 */
export async function authMiddleware(
  request: FastifyRequest,
  reply: FastifyReply,
) {
  try {
    // Получаем токен из header Authorization
    const authHeader = request.headers.authorization;

    if (!authHeader) {
      return reply.code(401).send({
        success: false,
        error: "Missing authorization header",
      });
    }

    // Проверяем формат: "Bearer <token>"
    const parts = authHeader.split(" ");

    if (parts.length !== 2 || parts[0] !== "Bearer") {
      return reply.code(401).send({
        success: false,
        error: "Invalid authorization header format. Use: Bearer <token>",
      });
    }

    const token = parts[1];

    // Проверяем токен
    const payload = JwtService.verify(token);

    if (!payload) {
      return reply.code(401).send({
        success: false,
        error: "Invalid or expired token",
      });
    }

    // Добавляем данные пользователя в request
    request.user = {
      username: payload.username,
      email: payload.email,
    };

    // Обновляем last_active для текущей сессии (с debounce 30 секунд)
    const now = Date.now();
    const lastUpdate = lastActivityUpdate.get(token) || 0;
    const timeSinceLastUpdate = now - lastUpdate;

    // Обновляем только если прошло больше 30 секунд с последнего обновления
    if (timeSinceLastUpdate > 30000) {
      lastActivityUpdate.set(token, now);

      pool
        .query("UPDATE sessions SET last_active = NOW() WHERE jwt_token = $1", [
          token,
        ])
        .then(() => {
          // После обновления last_active отправляем событие через Socket.IO
          const io = (request.server as any).io;
          if (io) {
            io.to(payload.username).emit("sessions:updated");
          }
        })
        .catch(() => {
          // Игнорируем ошибки обновления last_active
        });
    }

    // Продолжаем выполнение
  } catch (error) {
    return reply.code(500).send({
      success: false,
      error: "Authentication failed",
    });
  }
}
