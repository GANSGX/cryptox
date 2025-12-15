import { pool } from "../db/pool.js";
import type { Message, CreateMessageData } from "../types/message.types.js";

export class MessageService {
  /**
   * Создание chat_id из двух usernames (сортировка по алфавиту)
   */
  static createChatId(username1: string, username2: string): string {
    const sorted = [username1.toLowerCase(), username2.toLowerCase()].sort();
    return `${sorted[0]}_${sorted[1]}`;
  }

  /**
   * Отправка сообщения
   */
  static async createMessage(data: CreateMessageData): Promise<Message> {
    const chatId = this.createChatId(
      data.sender_username,
      data.recipient_username,
    );

    const result = await pool.query(
      `INSERT INTO messages (
        chat_id,
        sender_username,
        recipient_username,
        encrypted_content,
        message_type
      ) VALUES ($1, $2, $3, $4, $5)
      RETURNING *`,
      [
        chatId,
        data.sender_username.toLowerCase(),
        data.recipient_username.toLowerCase(),
        data.encrypted_content,
        data.message_type || "text",
      ],
    );

    return result.rows[0];
  }

  /**
   * Получение истории чата
   */
  static async getMessages(
    username1: string,
    username2: string,
    limit: number = 50,
    offset: number = 0,
  ): Promise<{ messages: Message[]; total: number }> {
    const chatId = this.createChatId(username1, username2);

    // Получаем сообщения
    const messagesResult = await pool.query(
      `SELECT * FROM messages
       WHERE chat_id = $1
       AND deleted_at IS NULL
       ORDER BY created_at DESC
       LIMIT $2 OFFSET $3`,
      [chatId, limit, offset],
    );

    // Подсчёт общего количества
    const countResult = await pool.query(
      `SELECT COUNT(*) as total FROM messages
       WHERE chat_id = $1
       AND deleted_at IS NULL`,
      [chatId],
    );

    return {
      messages: messagesResult.rows,
      total: parseInt(countResult.rows[0].total, 10),
    };
  }

  /**
   * Обновление статуса "доставлено"
   */
  static async markAsDelivered(messageId: string): Promise<void> {
    await pool.query(
      `UPDATE messages
       SET read_at = NULL
       WHERE id = $1
       AND read_at IS NULL`,
      [messageId],
    );
  }

  /**
   * Обновление статуса "прочитано"
   * ВАЖНО: Только получатель может пометить сообщение как прочитанное
   */
  static async markAsRead(
    messageId: string,
    username: string,
  ): Promise<boolean> {
    const result = await pool.query(
      `UPDATE messages
       SET read_at = NOW()
       WHERE id = $1
       AND recipient_username = $2
       AND read_at IS NULL`,
      [messageId, username.toLowerCase()],
    );

    // Возвращаем true если сообщение было обновлено
    return (result.rowCount ?? 0) > 0;
  }

  /**
   * Пометить все сообщения чата как прочитанные
   * Возвращает список id обновлённых сообщений для WebSocket уведомлений
   */
  static async markChatAsRead(
    username: string,
    otherUsername: string,
  ): Promise<string[]> {
    const chatId = this.createChatId(username, otherUsername);

    const result = await pool.query<{ id: string }>(
      `UPDATE messages
       SET read_at = NOW()
       WHERE chat_id = $1
       AND recipient_username = $2
       AND read_at IS NULL
       RETURNING id`,
      [chatId, username.toLowerCase()],
    );

    return result.rows.map((row) => row.id);
  }

  /**
   * Получение количества непрочитанных
   */
  static async getUnreadCount(
    username: string,
    otherUsername: string,
  ): Promise<number> {
    const chatId = this.createChatId(username, otherUsername);

    const result = await pool.query(
      `SELECT COUNT(*) as count FROM messages
       WHERE chat_id = $1
       AND recipient_username = $2
       AND read_at IS NULL
       AND deleted_at IS NULL`,
      [chatId, username.toLowerCase()],
    );

    return parseInt(result.rows[0].count, 10);
  }
}
