import type { FastifyRequest, FastifyReply } from 'fastify'
import { JwtService } from '../services/jwt.service.js'

// Расширяем тип FastifyRequest для добавления user
declare module 'fastify' {
  interface FastifyRequest {
    user?: {
      username: string
      email: string
    }
  }
}

/**
 * Middleware для проверки JWT токена
 */
export async function authMiddleware(
  request: FastifyRequest,
  reply: FastifyReply
) {
  try {
    // Получаем токен из header Authorization
    const authHeader = request.headers.authorization

    if (!authHeader) {
      return reply.code(401).send({
        success: false,
        error: 'Missing authorization header',
      })
    }

    // Проверяем формат: "Bearer <token>"
    const parts = authHeader.split(' ')
    
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return reply.code(401).send({
        success: false,
        error: 'Invalid authorization header format. Use: Bearer <token>',
      })
    }

    const token = parts[1]

    // Проверяем токен
    const payload = JwtService.verify(token)

    if (!payload) {
      return reply.code(401).send({
        success: false,
        error: 'Invalid or expired token',
      })
    }

    // Добавляем данные пользователя в request
    request.user = {
      username: payload.username,
      email: payload.email,
    }

    // Продолжаем выполнение
  } catch (error) {
    return reply.code(500).send({
      success: false,
      error: 'Authentication failed',
    })
  }
}