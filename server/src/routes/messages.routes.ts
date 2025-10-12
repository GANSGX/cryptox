import type { FastifyInstance } from 'fastify'
import { authMiddleware } from '../middleware/auth.middleware.js'
import { MessageService } from '../services/message.service.js'
import type {
  SendMessageRequest,
  SendMessageResponse,
  GetMessagesQuery,
  GetMessagesResponse,
  ApiResponse,
} from '../types/api.types.js'

export async function messagesRoutes(fastify: FastifyInstance) {
  /**
   * POST /messages
   * Отправка сообщения
   */
  fastify.post<{
    Body: SendMessageRequest
    Reply: ApiResponse<SendMessageResponse>
  }>(
    '/messages',
    {
      preHandler: authMiddleware,
    },
    async (request, reply) => {
      const { recipient_username, encrypted_content, message_type } = request.body
      const sender_username = request.user!.username

      // Валидация
      if (!recipient_username || !encrypted_content) {
        return reply.code(400).send({
          success: false,
          error: 'Missing required fields',
        })
      }

      // Нельзя отправить самому себе
      if (sender_username.toLowerCase() === recipient_username.toLowerCase()) {
        return reply.code(400).send({
          success: false,
          error: 'Cannot send message to yourself',
        })
      }

      // Создание сообщения
      const message = await MessageService.createMessage({
        sender_username,
        recipient_username,
        encrypted_content,
        message_type,
      })

      // Отправка через Socket.io (если получатель online)
      const io = fastify.io
      io.to(`user:${recipient_username.toLowerCase()}`).emit('new_message', {
        id: message.id,
        chat_id: message.chat_id,
        sender_username: message.sender_username,
        encrypted_content: message.encrypted_content,
        message_type: message.message_type,
        created_at: message.created_at.toISOString(),
      })

      return reply.code(201).send({
        success: true,
        data: {
          message_id: message.id,
          chat_id: message.chat_id,
          created_at: message.created_at.toISOString(),
          status: 'sent',
        },
      })
    }
  )

  /**
   * GET /messages/:username
   * Получение истории чата с пользователем
   */
  fastify.get<{
    Params: { username: string }
    Querystring: GetMessagesQuery
    Reply: ApiResponse<GetMessagesResponse>
  }>(
    '/messages/:username',
    {
      preHandler: authMiddleware,
    },
    async (request, reply) => {
      const { username: otherUsername } = request.params
      const { limit = 50, offset = 0 } = request.query
      const currentUsername = request.user!.username

      // Нельзя запросить чат с самим собой
      if (currentUsername.toLowerCase() === otherUsername.toLowerCase()) {
        return reply.code(400).send({
          success: false,
          error: 'Cannot get messages with yourself',
        })
      }

      // Получение сообщений
      const { messages, total } = await MessageService.getMessages(
        currentUsername,
        otherUsername,
        Number(limit),
        Number(offset)
      )

      // Форматирование
      const formattedMessages = messages.map((msg) => ({
        id: msg.id,
        sender_username: msg.sender_username,
        recipient_username: msg.recipient_username,
        encrypted_content: msg.encrypted_content,
        message_type: msg.message_type,
        created_at: msg.created_at.toISOString(),
        read_at: msg.read_at ? msg.read_at.toISOString() : null,
      }))

      return reply.code(200).send({
        success: true,
        data: {
          messages: formattedMessages,
          total,
          has_more: offset + messages.length < total,
        },
      })
    }
  )

  /**
   * PATCH /messages/:id/read
   * Пометить сообщение как прочитанное
   */
  fastify.patch<{
    Params: { id: string }
    Reply: ApiResponse
  }>(
    '/messages/:id/read',
    {
      preHandler: authMiddleware,
    },
    async (request, reply) => {
      const { id } = request.params

      await MessageService.markAsRead(id)

      // Уведомляем отправителя через Socket.io
      // (здесь нужно получить sender_username из БД, упростим)

      return reply.code(200).send({
        success: true,
        message: 'Message marked as read',
      })
    }
  )

  /**
   * PATCH /messages/chat/:username/read
   * Пометить все сообщения чата как прочитанные
   */
  fastify.patch<{
    Params: { username: string }
    Reply: ApiResponse
  }>(
    '/messages/chat/:username/read',
    {
      preHandler: authMiddleware,
    },
    async (request, reply) => {
      const { username: otherUsername } = request.params
      const currentUsername = request.user!.username

      await MessageService.markChatAsRead(currentUsername, otherUsername)

      return reply.code(200).send({
        success: true,
        message: 'All messages marked as read',
      })
    }
  )

  /**
   * GET /messages/chat/:username/unread
   * Получить количество непрочитанных сообщений
   */
  fastify.get<{
    Params: { username: string }
    Reply: ApiResponse<{ count: number }>
  }>(
    '/messages/chat/:username/unread',
    {
      preHandler: authMiddleware,
    },
    async (request, reply) => {
      const { username: otherUsername } = request.params
      const currentUsername = request.user!.username

      const count = await MessageService.getUnreadCount(currentUsername, otherUsername)

      return reply.code(200).send({
        success: true,
        data: { count },
      })
    }
  )
}