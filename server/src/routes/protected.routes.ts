import type { FastifyInstance } from 'fastify'
import { authMiddleware } from '../middleware/auth.middleware.js'

export async function protectedRoutes(fastify: FastifyInstance) {
  
  /**
   * GET /me
   * Получение информации о текущем пользователе
   */
  fastify.get('/me', {
    preHandler: authMiddleware,
  }, async (request, reply) => {
    // request.user доступен благодаря middleware
    return reply.code(200).send({
      success: true,
      data: {
        username: request.user!.username,
        email: request.user!.email,
        message: 'Authenticated successfully',
      },
    })
  })
}