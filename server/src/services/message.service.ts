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
        message_type,
        media_id
      ) VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *`,
      [
        chatId,
        data.sender_username.toLowerCase(),
        data.recipient_username.toLowerCase(),
        data.encrypted_content,
        data.message_type || "text",
        data.media_id || null,
      ],
    );

    return result.rows[0];
  }

  /**
   * Получение истории чата
   * Фильтрует удаленные сообщения в зависимости от пользователя
   */
  static async getMessages(
    username1: string,
    username2: string,
    limit: number = 50,
    offset: number = 0,
  ): Promise<{ messages: Message[]; total: number }> {
    const chatId = this.createChatId(username1, username2);
    const currentUser = username1.toLowerCase();

    // Получаем сообщения с учетом флагов удаления
    // Не показываем сообщения если:
    // - deleted_for_sender = true И я отправитель
    // - deleted_for_recipient = true И я получатель
    const messagesResult = await pool.query(
      `SELECT * FROM messages
       WHERE chat_id = $1
       AND deleted_at IS NULL
       AND NOT (
         (deleted_for_sender = true AND sender_username = $2) OR
         (deleted_for_recipient = true AND recipient_username = $2)
       )
       ORDER BY created_at DESC
       LIMIT $3 OFFSET $4`,
      [chatId, currentUser, limit, offset],
    );

    // Подсчёт общего количества
    const countResult = await pool.query(
      `SELECT COUNT(*) as total FROM messages
       WHERE chat_id = $1
       AND deleted_at IS NULL
       AND NOT (
         (deleted_for_sender = true AND sender_username = $2) OR
         (deleted_for_recipient = true AND recipient_username = $2)
       )`,
      [chatId, currentUser],
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

  /**
   * Получение сообщения по ID
   */
  static async getMessageById(messageId: string): Promise<Message | null> {
    const result = await pool.query<Message>(
      `SELECT * FROM messages WHERE id = $1`,
      [messageId],
    );

    return result.rows.length > 0 ? result.rows[0] : null;
  }

  /**
   * Редактирование сообщения
   */
  static async editMessage(
    messageId: string,
    encrypted_content: string,
  ): Promise<void> {
    await pool.query(
      `UPDATE messages
       SET encrypted_content = $1, edited_at = NOW()
       WHERE id = $2`,
      [encrypted_content, messageId],
    );
  }

  /**
   * Удаление сообщения для отправителя (deleted_for_sender = true)
   */
  static async deleteMessageForSender(messageId: string): Promise<void> {
    await pool.query(
      `UPDATE messages
       SET deleted_for_sender = true
       WHERE id = $1`,
      [messageId],
    );
  }

  /**
   * Удаление сообщения для получателя (deleted_for_recipient = true)
   */
  static async deleteMessageForRecipient(messageId: string): Promise<void> {
    await pool.query(
      `UPDATE messages
       SET deleted_for_recipient = true
       WHERE id = $1`,
      [messageId],
    );
  }

  /**
   * Удаление сообщения для всех (оба флага = true)
   */
  static async deleteMessageForEveryone(messageId: string): Promise<void> {
    await pool.query(
      `UPDATE messages
       SET deleted_for_sender = true, deleted_for_recipient = true
       WHERE id = $1`,
      [messageId],
    );
  }
}
