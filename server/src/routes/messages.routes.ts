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
        delivered_at: null, // Новое сообщение еще не доставлено
        read_at: null, // Новое сообщение еще не прочитано
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
        delivered_at: msg.delivered_at ? msg.delivered_at.toISOString() : null,
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

      // Получить список обновлённых сообщений
      const updatedMessageIds = await MessageService.markChatAsRead(
        currentUsername,
        otherUsername,
      );

      // Отправить WebSocket уведомления отправителю для каждого сообщения
      const io = fastify.io;
      if (io && updatedMessageIds.length > 0) {
        updatedMessageIds.forEach((messageId) => {
          io.to(`user:${otherUsername.toLowerCase()}`).emit(
            "message_status_update",
            {
              messageId,
              status: "read",
            },
          );
        });
      }

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

  /**
   * GET /sync
   * Полная синхронизация контактов и истории (Telegram-style)
   * Возвращает:
   * - Список всех контактов с последним сообщением
   * - Количество непрочитанных для каждого
   */
  fastify.get<{
    Reply: ApiResponse<{
      contacts: Array<{
        username: string;
        lastMessage: string;
        lastMessageTime: string;
        unreadCount: number;
        isOnline?: boolean;
      }>;
    }>;
  }>(
    "/sync",
    {
      preHandler: authMiddleware,
    },
    async (request, reply) => {
      const currentUsername = request.user!.username;

      try {
        const { pool } = await import("../db/pool.js");

        // Запрос для получения всех контактов с последним сообщением
        const contactsResult = await pool.query(
          `WITH ranked_messages AS (
            SELECT
              CASE
                WHEN sender_username = $1 THEN recipient_username
                ELSE sender_username
              END as contact_username,
              encrypted_content,
              created_at,
              sender_username,
              ROW_NUMBER() OVER (
                PARTITION BY
                  CASE
                    WHEN sender_username = $1 THEN recipient_username
                    ELSE sender_username
                  END
                ORDER BY created_at DESC
              ) as rn
            FROM messages
            WHERE sender_username = $1 OR recipient_username = $1
          ),
          unread_counts AS (
            SELECT
              sender_username as contact_username,
              COUNT(*) as unread_count
            FROM messages
            WHERE recipient_username = $1 AND read_at IS NULL
            GROUP BY sender_username
          )
          SELECT
            rm.contact_username as username,
            rm.encrypted_content as last_message,
            rm.created_at as last_message_time,
            COALESCE(uc.unread_count, 0) as unread_count
          FROM ranked_messages rm
          LEFT JOIN unread_counts uc ON rm.contact_username = uc.contact_username
          WHERE rm.rn = 1
          ORDER BY rm.created_at DESC`,
          [currentUsername.toLowerCase()],
        );

        const contacts = contactsResult.rows.map((row) => ({
          username: row.username,
          lastMessage: row.last_message,
          lastMessageTime: row.last_message_time.toISOString(),
          unreadCount: parseInt(row.unread_count),
          isOnline: false, // TODO: implement online status tracking
        }));

        console.log(
          `🔄 [/sync] Returning ${contacts.length} contacts to ${currentUsername}`,
        );

        return reply.code(200).send({
          success: true,
          data: { contacts },
        });
      } catch (error) {
        fastify.log.error({ error }, "Error in /sync endpoint");
        return reply.code(500).send({
          success: false,
          error: "Failed to sync contacts",
        });
      }
    },
  );
}
