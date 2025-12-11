import type { FastifyInstance } from "fastify";
import { authMiddleware } from "../middleware/auth.middleware.js";
import { MessageService } from "../services/message.service.js";
import { sanitizeUsername } from "../utils/sanitize.js";
import type {
  SendMessageRequest,
  SendMessageResponse,
  GetMessagesQuery,
  GetMessagesResponse,
  ApiResponse,
} from "../types/api.types.js";

export async function messagesRoutes(fastify: FastifyInstance) {
  /**
   * POST /messages
   * Отправка сообщения
   */
  fastify.post<{
    Body: SendMessageRequest;
    Reply: ApiResponse<SendMessageResponse>;
  }>(
    "/messages",
    {
      preHandler: authMiddleware,
    },
    async (request, reply) => {
      let { recipient_username, encrypted_content, message_type } =
        request.body;
      const sender_username = request.user!.username;

      // Sanitize inputs to prevent XSS
      recipient_username = sanitizeUsername(recipient_username);

      // Валидация
      if (!recipient_username || !encrypted_content) {
        return reply.code(400).send({
          success: false,
          error: "Missing required fields",
        });
      }

      // Проверка типа данных
      if (typeof encrypted_content !== "string") {
        return reply.code(400).send({
          success: false,
          error: "Invalid encrypted_content type",
        });
      }

      // Проверка максимальной длины (50KB для зашифрованного текста)
      // Plain text max 10,000 символов → зашифрованный ~20-30KB
      if (encrypted_content.length > 50000) {
        return reply.code(400).send({
          success: false,
          error: "Message too long (max 50KB encrypted)",
        });
      }

      // Проверка на подозрительные паттерны (базовая защита от инъекций)
      // Зашифрованный текст должен быть base64-подобным
      if (!/^[A-Za-z0-9+/=:]+$/.test(encrypted_content)) {
        return reply.code(400).send({
          success: false,
          error: "Invalid encrypted_content format",
        });
      }

      // Разрешаем отправку самому себе (Saved Messages / Избранное)

      // Создание сообщения
      const message = await MessageService.createMessage({
        sender_username,
        recipient_username,
        encrypted_content,
        message_type,
      });

      // Отправка через Socket.io (если получатель online)
      const io = fastify.io;
      io.to(`user:${recipient_username.toLowerCase()}`).emit("new_message", {
        message_id: message.id, // Клиент ожидает message_id, не id
        chat_id: message.chat_id,
        sender_username: message.sender_username,
        recipient_username: message.recipient_username, // Добавлено для клиента
        encrypted_content: message.encrypted_content,
        message_type: message.message_type,
        created_at: message.created_at.toISOString(),
      });

      return reply.code(201).send({
        success: true,
        data: {
          message_id: message.id,
          chat_id: message.chat_id,
          created_at: message.created_at.toISOString(),
          status: "sent",
        },
      });
    },
  );

  /**
   * GET /messages/:username
   * Получение истории чата с пользователем
   */
  fastify.get<{
    Params: { username: string };
    Querystring: GetMessagesQuery;
    Reply: ApiResponse<GetMessagesResponse>;
  }>(
    "/messages/:username",
    {
      preHandler: authMiddleware,
    },
    async (request, reply) => {
      const { username: otherUsername } = request.params;
      let { limit = 50, offset = 0 } = request.query;
      const currentUsername = request.user!.username;

      // Валидация limit и offset
      limit = Number(limit);
      offset = Number(offset);

      if (isNaN(limit) || isNaN(offset)) {
        return reply.code(400).send({
          success: false,
          error: "Invalid limit or offset value",
        });
      }

      if (limit < 1 || limit > 100) {
        return reply.code(400).send({
          success: false,
          error: "Limit must be between 1 and 100",
        });
      }

      if (offset < 0) {
        return reply.code(400).send({
          success: false,
          error: "Offset must be non-negative",
        });
      }

      // Разрешаем чат с самим собой (Saved Messages / Избранное)

      // Получение сообщений
      const { messages, total } = await MessageService.getMessages(
        currentUsername,
        otherUsername,
        limit,
        offset,
      );

      // Форматирование
      const formattedMessages = messages.map((msg) => ({
        id: msg.id,
        sender_username: msg.sender_username,
        recipient_username: msg.recipient_username,
        encrypted_content: msg.encrypted_content,
        message_type: msg.message_type,
        created_at: msg.created_at.toISOString(),
        read_at: msg.read_at ? msg.read_at.toISOString() : null,
      }));

      return reply.code(200).send({
        success: true,
        data: {
          messages: formattedMessages,
          total,
          has_more: offset + messages.length < total,
        },
      });
    },
  );

  /**
   * PATCH /messages/:id/read
   * Пометить сообщение как прочитанное
   */
  fastify.patch<{
    Params: { id: string };
    Reply: ApiResponse;
  }>(
    "/messages/:id/read",
    {
      preHandler: authMiddleware,
    },
    async (request, reply) => {
      const { id } = request.params;
      const currentUsername = request.user!.username;

      // Пометить как прочитанное (только если текущий пользователь - получатель)
      const updated = await MessageService.markAsRead(id, currentUsername);

      if (!updated) {
        return reply.code(404).send({
          success: false,
          error: "Message not found or already read",
        });
      }

      // Уведомляем отправителя через Socket.io
      // (здесь нужно получить sender_username из БД, упростим)

      return reply.code(200).send({
        success: true,
        message: "Message marked as read",
      });
    },
  );

  /**
   * PATCH /messages/chat/:username/read
   * Пометить все сообщения чата как прочитанные
   */
  fastify.patch<{
    Params: { username: string };
    Reply: ApiResponse;
  }>(
    "/messages/chat/:username/read",
    {
      preHandler: authMiddleware,
    },
    async (request, reply) => {
      const { username: otherUsername } = request.params;
      const currentUsername = request.user!.username;

      await MessageService.markChatAsRead(currentUsername, otherUsername);

      return reply.code(200).send({
        success: true,
        message: "All messages marked as read",
      });
    },
  );

  /**
   * GET /messages/chat/:username/unread
   * Получить количество непрочитанных сообщений
   */
  fastify.get<{
    Params: { username: string };
    Reply: ApiResponse<{ count: number }>;
  }>(
    "/messages/chat/:username/unread",
    {
      preHandler: authMiddleware,
    },
    async (request, reply) => {
      const { username: otherUsername } = request.params;
      const currentUsername = request.user!.username;

      const count = await MessageService.getUnreadCount(
        currentUsername,
        otherUsername,
      );

      return reply.code(200).send({
        success: true,
        data: { count },
      });
    },
  );
}
