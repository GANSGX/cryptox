import { Server as SocketIOServer, Socket } from 'socket.io'
import type { Server as HTTPServer } from 'http'
import { JwtService } from '../services/jwt.service.js'
import { log } from '../services/logger.service.js'
import { env } from '../config/env.js'

// Расширяем тип Socket для добавления user
interface AuthenticatedSocket extends Socket {
  user?: {
    username: string
    email: string
  }
}

export function initializeSocketServer(httpServer: HTTPServer) {
  const io = new SocketIOServer(httpServer, {
    cors: {
      origin: (origin, callback) => {
        // Разрешаем null origin (для file://)
        if (!origin) {
          callback(null, true)
          return
        }
        
        // Разрешаем localhost и file:// для разработки
        if (origin.includes('localhost') || origin.includes('127.0.0.1') || origin.startsWith('file://')) {
          callback(null, true)
          return
        }
        
        // В production проверяем env.CORS_ORIGIN
        if (origin === env.CORS_ORIGIN) {
          callback(null, true)
          return
        }
        
        callback(new Error('Not allowed by CORS'), false)
      },
      credentials: true,
      methods: ['GET', 'POST'],
    },
  })

  // Middleware для аутентификации
  io.use((socket: AuthenticatedSocket, next) => {
    const token = socket.handshake.auth.token as string

    if (!token) {
      log.warn('Socket connection rejected: No token provided', {
        socketId: socket.id,
        ip: socket.handshake.address,
      })
      return next(new Error('Authentication error: No token provided'))
    }

    // Проверяем JWT токен
    const payload = JwtService.verify(token)

    if (!payload) {
      log.warn('Socket connection rejected: Invalid token', {
        socketId: socket.id,
        ip: socket.handshake.address,
      })
      return next(new Error('Authentication error: Invalid token'))
    }

    // Добавляем данные пользователя к сокету
    socket.user = {
      username: payload.username,
      email: payload.email,
    }

    log.info('Socket authenticated', {
      socketId: socket.id,
      username: payload.username,
    })

    next()
  })

  // Подключение клиента
  io.on('connection', (socket: AuthenticatedSocket) => {
    const username = socket.user?.username || 'unknown'

    log.info('Client connected', {
      socketId: socket.id,
      username,
    })

    // Подписываем пользователя на его личный room
    socket.join(`user:${username}`)

    // Отправляем подтверждение подключения
    socket.emit('connected', {
      message: 'Successfully connected to CryptoX',
      username,
    })

    // Обработчик отключения
    socket.on('disconnect', (reason: string) => {
      log.info('Client disconnected', {
        socketId: socket.id,
        username,
        reason,
      })
    })

    // Typing indicators
    socket.on('typing_start', (data: { chatId: string }) => {
      log.debug('Typing start', { username, chatId: data.chatId })
      socket.to(`user:${data.chatId}`).emit('user_typing', {
        username,
        chatId: data.chatId,
      })
    })

    socket.on('typing_stop', (data: { chatId: string }) => {
      log.debug('Typing stop', { username, chatId: data.chatId })
      socket.to(`user:${data.chatId}`).emit('user_stopped_typing', {
        username,
        chatId: data.chatId,
      })
    })

    // Присоединение к группе
    socket.on('join_group', (data: { groupId: string }) => {
      socket.join(`group:${data.groupId}`)
      log.info('User joined group', {
        username,
        groupId: data.groupId,
      })
    })

    // Выход из группы
    socket.on('leave_group', (data: { groupId: string }) => {
      socket.leave(`group:${data.groupId}`)
      log.info('User left group', {
        username,
        groupId: data.groupId,
      })
    })

    // Обработка ошибок
    socket.on('error', (error: Error) => {
      log.error('Socket error', {
        socketId: socket.id,
        username,
        error: error.message,
      })
    })
  })

  log.info('Socket.io server initialized')

  return io
}