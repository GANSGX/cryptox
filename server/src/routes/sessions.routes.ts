import type { FastifyInstance } from 'fastify'
import { authMiddleware } from '../middleware/auth.middleware'
import { pool } from '../db/pool'

export async function sessionsRoutes(fastify: FastifyInstance) {
  /**
   * GET /sessions
   * Получить список активных сессий пользователя
   */
  fastify.get('/sessions', { 
    preHandler: authMiddleware 
  }, async (request, reply) => {
    const username = (request as any).user.username

    try {
      const result = await pool.query(
        `SELECT 
          id,
          device_info,
          ip_address,
          created_at,
          last_active,
          expires_at,
          (jwt_token = $2) as is_current
         FROM sessions 
         WHERE username = $1 AND expires_at > NOW()
         ORDER BY last_active DESC`,
        [username, request.headers.authorization?.replace('Bearer ', '')]
      )

      // Парсим device_info из строки в объект
      const sessions = result.rows.map(row => ({
        ...row,
        device_info: typeof row.device_info === 'string' 
          ? JSON.parse(row.device_info) 
          : row.device_info
      }))

      return reply.send({
        success: true,
        sessions,
      })
    } catch (error) {
      fastify.log.error({ error }, 'Get sessions error')
      return reply.status(500).send({
        success: false,
        error: 'Failed to get sessions',
      })
    }
  })

  /**
   * DELETE /sessions/others
   * Выйти со всех других устройств (кроме текущего)
   * ВАЖНО: Должен быть ПЕРЕД /:sessionId для правильного роутинга
   */
  fastify.delete('/sessions/others', { 
    preHandler: authMiddleware 
  }, async (request, reply) => {
    const username = (request as any).user.username
    const currentToken = request.headers.authorization?.replace('Bearer ', '')

    try {
      const result = await pool.query(
        'DELETE FROM sessions WHERE username = $1 AND jwt_token != $2 RETURNING id',
        [username, currentToken]
      )

      return reply.send({
        success: true,
        message: `Terminated ${result.rowCount} sessions`,
        count: result.rowCount,
      })
    } catch (error) {
      fastify.log.error({ error }, 'Delete other sessions error')
      return reply.status(500).send({
        success: false,
        error: 'Failed to delete sessions',
      })
    }
  })

  /**
   * DELETE /sessions/:sessionId
   * Удалить конкретную сессию (выйти с устройства)
   */
  fastify.delete<{
    Params: { sessionId: string }
  }>('/sessions/:sessionId', { preHandler: authMiddleware }, async (request, reply) => {
    const username = (request as any).user.username
    const { sessionId } = request.params

    try {
      const result = await pool.query(
        'DELETE FROM sessions WHERE id = $1 AND username = $2 RETURNING id',
        [sessionId, username]
      )

      if (result.rowCount === 0) {
        return reply.status(404).send({
          success: false,
          error: 'Session not found',
        })
      }

      return reply.send({
        success: true,
        message: 'Session terminated',
      })
    } catch (error) {
      fastify.log.error({ error }, 'Delete session error')
      return reply.status(500).send({
        success: false,
        error: 'Failed to delete session',
      })
    }
  })
}