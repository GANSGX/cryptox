import type { FastifyInstance } from 'fastify'
import { authMiddleware } from '../middleware/auth.middleware.js'
import { UserService } from '../services/user.service.js'

export async function protectedRoutes(fastify: FastifyInstance) {
  
  /**
   * GET /me
   * Получение информации о текущем пользователе
   */
  fastify.get('/me', {
    preHandler: authMiddleware,
  }, async (request, reply) => {
    try {
      console.log('🔍 /me called, user:', request.user)
      
      // Получаем полную информацию о пользователе из БД
      const user = await UserService.getUserByUsername(request.user!.username)
      
      console.log('📦 User from DB:', user)
      
      if (!user) {
        return reply.code(404).send({
          success: false,
          error: 'User not found',
        })
      }

      return reply.code(200).send({
        success: true,
        data: {
          username: user.username,
          email: user.email,
          email_verified: user.email_verified,
        },
        message: 'Authenticated successfully',
      })
    } catch (error) {
      console.error('❌ Error in /me:', error)
      return reply.code(500).send({
        success: false,
        error: 'Internal server error',
      })
    }
  })
}