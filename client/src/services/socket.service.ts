import { io, Socket } from "socket.io-client";

class SocketService {
  private socket: Socket | null = null;

  /**
   * Подключение к Socket.io
   */
  connect(token: string) {
    if (this.socket?.connected) {
      return;
    }

    const serverUrl = `http://${window.location.hostname}:3001`;
    this.socket = io(serverUrl, {
      auth: {
        token,
      },
    });

    this.socket.on("connect", () => {
      console.log("✅ Socket.io connected:", this.socket?.id);
    });

    this.socket.on("disconnect", (reason) => {
      console.log("❌ Socket.io disconnected:", reason);
    });

    this.socket.on("connect_error", (error) => {
      console.error("🔴 Socket.io connection error:", error.message);
    });

    this.socket.on("connected", (data) => {
      console.log("✅ Server confirmation:", data);
    });
  }

  /**
   * Подключение для pending approval (БЕЗ токена, с pending_session_id)
   */
  connectForPendingApproval(pending_session_id: string) {
    if (this.socket?.connected) {
      this.disconnect();
    }

    const serverUrl = `http://${window.location.hostname}:3001`;
    this.socket = io(serverUrl, {
      auth: {
        pending_session_id,
      },
    });

    this.socket.on("connect", () => {
      console.log(
        "✅ Socket.io connected for pending approval:",
        this.socket?.id,
      );
    });

    this.socket.on("disconnect", (reason) => {
      console.log("❌ Socket.io disconnected:", reason);
    });

    this.socket.on("connect_error", (error) => {
      console.error("🔴 Socket.io connection error:", error.message);
    });

    this.socket.on("connected", (data) => {
      console.log("✅ Server confirmation:", data);
    });
  }

  /**
   * Отключение
   */
  disconnect() {
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
  }

  /**
   * Получение инстанса сокета
   */
  getSocket(): Socket | null {
    return this.socket;
  }

  /**
   * Отправка события typing_start
   */
  emitTypingStart(chatId: string) {
    this.socket?.emit("typing_start", { chatId });
  }

  /**
   * Отправка события typing_stop
   */
  emitTypingStop(chatId: string) {
    this.socket?.emit("typing_stop", { chatId });
  }

  /**
   * Подтверждение доставки
   */
  emitMessageDelivered(messageId: string, toUsername: string) {
    this.socket?.emit("message_delivered", { messageId, toUsername });
  }

  /**
   * Подтверждение прочтения
   */
  emitMessageRead(messageId: string, toUsername: string) {
    const msg = `🔵 EMIT message_read: id=${messageId.slice(0, 8)}... to=${toUsername}`;
    console.log(msg);

    // Import debugLogger dynamically to avoid circular deps
    import("@/utils/debugLogger").then(({ debugLogger }) => {
      debugLogger.log(msg);
    });

    this.socket?.emit("message_read", { messageId, toUsername });
  }

  /**
   * Подписка на новые сообщения
   */
  onNewMessage(
    callback: (data: {
      message_id: string;
      sender_username: string;
      recipient_username: string;
      encrypted_content: string;
      message_type: "text" | "image" | "video" | "file" | "audio";
      created_at: string;
      delivered_at: string | null;
      read_at: string | null;
    }) => void,
  ) {
    this.socket?.on("new_message", callback);
  }

  /**
   * Отписка от новых сообщений
   */
  offNewMessage(
    callback: (data: {
      message_id: string;
      sender_username: string;
      recipient_username: string;
      encrypted_content: string;
      message_type: "text" | "image" | "video" | "file" | "audio";
      created_at: string;
      delivered_at: string | null;
      read_at: string | null;
    }) => void,
  ) {
    this.socket?.off("new_message", callback);
  }

  /**
   * Подписка на typing
   */
  onUserTyping(callback: (data: { username: string; chatId: string }) => void) {
    this.socket?.on("user_typing", callback);
  }

  /**
   * Отписка от typing
   */
  offUserTyping(
    callback: (data: { username: string; chatId: string }) => void,
  ) {
    this.socket?.off("user_typing", callback);
  }

  /**
   * Подписка на stopped typing
   */
  onUserStoppedTyping(
    callback: (data: { username: string; chatId: string }) => void,
  ) {
    this.socket?.on("user_stopped_typing", callback);
  }

  /**
   * Отписка от stopped typing
   */
  offUserStoppedTyping(
    callback: (data: { username: string; chatId: string }) => void,
  ) {
    this.socket?.off("user_stopped_typing", callback);
  }

  /**
   * Подписка на обновление статуса сообщения
   */
  onMessageStatusUpdate(
    callback: (data: {
      messageId: string;
      status: "delivered" | "read";
    }) => void,
  ) {
    this.socket?.on("message_status_update", callback);
  }

  /**
   * Отписка от обновления статуса
   */
  offMessageStatusUpdate(
    callback: (data: {
      messageId: string;
      status: "delivered" | "read";
    }) => void,
  ) {
    this.socket?.off("message_status_update", callback);
  }

  /**
   * Подписка на обновление списка сессий
   */
  onSessionsUpdated(callback: () => void) {
    this.socket?.on("sessions:updated", callback);
  }

  /**
   * Отписка от обновления списка сессий
   */
  offSessionsUpdated(callback: () => void) {
    this.socket?.off("sessions:updated", callback);
  }

  /**
   * Подписка на завершение сессии
   */
  onSessionTerminated(
    callback: (data: { sessionId: string; message: string }) => void,
  ) {
    this.socket?.on("session:terminated", callback);
  }

  /**
   * Отписка от завершения сессии
   */
  offSessionTerminated(
    callback: (data: { sessionId: string; message: string }) => void,
  ) {
    this.socket?.off("session:terminated", callback);
  }

  /**
   * Подписка на обновление аватарки пользователя
   */
  onAvatarUpdated(
    callback: (data: { username: string; avatar_path: string | null }) => void,
  ) {
    this.socket?.on("avatar_updated", callback);
  }

  /**
   * Отписка от обновления аватарки
   */
  offAvatarUpdated(
    callback: (data: { username: string; avatar_path: string | null }) => void,
  ) {
    this.socket?.off("avatar_updated", callback);
  }

  /**
   * Подписка на произвольное событие
   */
  on(event: string, callback: (...args: unknown[]) => void) {
    this.socket?.on(event, callback);
  }

  /**
   * Отписка от произвольного события
   */
  off(event: string, callback: (...args: unknown[]) => void) {
    this.socket?.off(event, callback);
  }
}

export const socketService = new SocketService();
