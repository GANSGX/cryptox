import { Server as SocketIOServer, Socket } from "socket.io";
import type { Server as HTTPServer } from "http";
import { JwtService } from "../services/jwt.service.js";
import { log } from "../services/logger.service.js";
import { env } from "../config/env.js";
import { pool } from "../db/pool.js";

// Расширяем тип Socket для добавления user
interface AuthenticatedSocket extends Socket {
  user?: {
    username: string;
    email: string;
  };
}

export function initializeSocketServer(httpServer: HTTPServer) {
  const io = new SocketIOServer(httpServer, {
    cors: {
      origin: (origin, callback) => {
        if (!origin) {
          callback(null, true);
          return;
        }

        if (
          origin.includes("localhost") ||
          origin.includes("127.0.0.1") ||
          origin.startsWith("file://")
        ) {
          callback(null, true);
          return;
        }

        if (origin === env.CORS_ORIGIN) {
          callback(null, true);
          return;
        }

        callback(new Error("Not allowed by CORS"), false);
      },
      credentials: true,
      methods: ["GET", "POST"],
    },
  });

  // Middleware для аутентификации
  io.use((socket: AuthenticatedSocket, next) => {
    const token = socket.handshake.auth.token as string;
    const pending_session_id = socket.handshake.auth
      .pending_session_id as string;

    // Разрешаем подключение БЕЗ токена если есть pending_session_id (для device approval)
    if (pending_session_id) {
      log.info("Socket connection for pending approval", {
        socketId: socket.id,
        pending_session_id,
      });
      return next();
    }

    if (!token) {
      log.warn("Socket connection rejected: No token provided", {
        socketId: socket.id,
        ip: socket.handshake.address,
      });
      return next(new Error("Authentication error: No token provided"));
    }

    const payload = JwtService.verify(token);

    if (!payload) {
      log.warn("Socket connection rejected: Invalid token", {
        socketId: socket.id,
        ip: socket.handshake.address,
      });
      return next(new Error("Authentication error: Invalid token"));
    }

    socket.user = {
      username: payload.username,
      email: payload.email,
    };

    log.info("Socket authenticated", {
      socketId: socket.id,
      username: payload.username,
    });

    next();
  });

  // Подключение клиента
  io.on("connection", (socket: AuthenticatedSocket) => {
    const username = socket.user?.username || "unknown";
    const pending_session_id = socket.handshake.auth
      .pending_session_id as string;

    log.info("Client connected", {
      socketId: socket.id,
      username,
      pending_session_id,
    });

    // Если есть pending_session_id - join к этому room (для device approval)
    if (pending_session_id) {
      socket.join(pending_session_id);
      console.log(
        `✅ Socket ${socket.id} joined pending session room: ${pending_session_id}`,
      );
    } else {
      // Обычное подключение - подписываем на username room
      socket.join(`user:${username.toLowerCase()}`);
      console.log(
        `✅ Socket ${socket.id} joined room: user:${username.toLowerCase()}`,
      );
    }

    // Отправляем подтверждение подключения
    socket.emit("connected", {
      message: "Successfully connected to CryptoX",
      username,
    });

    // Обработчик отключения
    socket.on("disconnect", (reason: string) => {
      log.info("Client disconnected", {
        socketId: socket.id,
        username,
        reason,
      });
    });

    // Typing indicators
    socket.on("typing_start", (data: { chatId: string }) => {
      // Проверяем что пользователь имеет доступ к этому чату
      // chatId имеет формат "user1_user2" (отсортированные по алфавиту)
      if (!username || username === "unknown") {
        log.warn("Unauthorized typing_start - no username", {
          socketId: socket.id,
          chatId: data.chatId,
        });
        return;
      }

      const chatUsers = data.chatId.split("_");
      if (
        chatUsers.length !== 2 ||
        !chatUsers.includes(username.toLowerCase())
      ) {
        log.warn("Unauthorized typing_start - user not in chat", {
          username,
          chatId: data.chatId,
        });
        return;
      }

      log.debug("Typing start", { username, chatId: data.chatId });
      socket.to(data.chatId).emit("user_typing", {
        username,
        chatId: data.chatId,
      });
    });

    socket.on("typing_stop", (data: { chatId: string }) => {
      // Проверяем что пользователь имеет доступ к этому чату
      if (!username || username === "unknown") {
        log.warn("Unauthorized typing_stop - no username", {
          socketId: socket.id,
          chatId: data.chatId,
        });
        return;
      }

      const chatUsers = data.chatId.split("_");
      if (
        chatUsers.length !== 2 ||
        !chatUsers.includes(username.toLowerCase())
      ) {
        log.warn("Unauthorized typing_stop - user not in chat", {
          username,
          chatId: data.chatId,
        });
        return;
      }

      log.debug("Typing stop", { username, chatId: data.chatId });
      socket.to(data.chatId).emit("user_stopped_typing", {
        username,
        chatId: data.chatId,
      });
    });

    // Подтверждение доставки сообщения
    socket.on(
      "message_delivered",
      async (data: { messageId: string; toUsername: string }) => {
        // Проверяем что сообщение принадлежит текущему пользователю (recipient)
        if (!username || username === "unknown") {
          log.warn("Unauthorized message_delivered - no username", {
            socketId: socket.id,
            messageId: data.messageId,
          });
          return;
        }

        try {
          // Обновляем delivered_at в БД и проверяем авторизацию одним запросом
          const result = await pool.query(
            "UPDATE messages SET delivered_at = NOW() WHERE id = $1 AND recipient_username = $2 AND delivered_at IS NULL RETURNING id",
            [data.messageId, username.toLowerCase()],
          );

          if (result.rows.length === 0) {
            log.warn("Unauthorized message_delivered or already delivered", {
              username,
              messageId: data.messageId,
            });
            return;
          }

          log.debug("Message delivered", {
            messageId: data.messageId,
            username,
          });

          // Отправляем уведомление отправителю
          socket
            .to(`user:${data.toUsername.toLowerCase()}`)
            .emit("message_status_update", {
              messageId: data.messageId,
              status: "delivered",
            });
        } catch (error) {
          log.error("Error in message_delivered", {
            error,
            username,
            messageId: data.messageId,
          });
        }
      },
    );

    // Подтверждение прочтения сообщения
    socket.on(
      "message_read",
      async (data: { messageId: string; toUsername: string }) => {
        // Проверяем что сообщение принадлежит текущему пользователю (recipient)
        if (!username || username === "unknown") {
          log.warn("Unauthorized message_read - no username", {
            socketId: socket.id,
            messageId: data.messageId,
          });
          return;
        }

        try {
          // Обновляем read_at в БД и проверяем авторизацию одним запросом
          const result = await pool.query(
            "UPDATE messages SET read_at = NOW() WHERE id = $1 AND recipient_username = $2 AND read_at IS NULL RETURNING id",
            [data.messageId, username.toLowerCase()],
          );

          if (result.rows.length === 0) {
            log.warn("Unauthorized message_read or already read", {
              username,
              messageId: data.messageId,
            });
            return;
          }

          log.debug("Message read", { messageId: data.messageId, username });

          // Отправляем уведомление отправителю
          socket
            .to(`user:${data.toUsername.toLowerCase()}`)
            .emit("message_status_update", {
              messageId: data.messageId,
              status: "read",
            });
        } catch (error) {
          log.error("Error in message_read", {
            error,
            username,
            messageId: data.messageId,
          });
        }
      },
    );

    // Присоединение к группе
    socket.on("join_group", async (data: { groupId: string }) => {
      // Проверяем что пользователь является членом группы
      if (!username || username === "unknown") {
        log.warn("Unauthorized join_group attempt - no username", {
          socketId: socket.id,
          groupId: data.groupId,
        });
        socket.emit("error", { message: "Unauthorized" });
        return;
      }

      try {
        const result = await pool.query(
          "SELECT 1 FROM group_members WHERE group_id = $1 AND username = $2",
          [data.groupId, username.toLowerCase()],
        );

        if (result.rows.length === 0) {
          log.warn("Unauthorized join_group attempt - not a member", {
            username,
            groupId: data.groupId,
          });
          socket.emit("error", { message: "Access denied to this group" });
          return;
        }

        socket.join(`group:${data.groupId}`);
        log.info("User joined group", {
          username,
          groupId: data.groupId,
        });
      } catch (error) {
        log.error("Error in join_group", {
          error,
          username,
          groupId: data.groupId,
        });
        socket.emit("error", { message: "Failed to join group" });
      }
    });

    // Выход из группы
    socket.on("leave_group", (data: { groupId: string }) => {
      socket.leave(`group:${data.groupId}`);
      log.info("User left group", {
        username,
        groupId: data.groupId,
      });
    });

    // Обработка ошибок
    socket.on("error", (error: Error) => {
      log.error("Socket error", {
        socketId: socket.id,
        username,
        error: error.message,
      });
    });
  });

  log.info("Socket.io server initialized");

  return io;
}
