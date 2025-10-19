import { io, Socket } from 'socket.io-client'

class SocketService {
  private socket: Socket | null = null

  /**
   * Подключение к Socket.io
   */
  connect(token: string) {
    if (this.socket?.connected) {
      return
    }

    this.socket = io('http://localhost:3001', {
      auth: {
        token,
      },
    })

    this.socket.on('connect', () => {
      console.log('✅ Socket.io connected:', this.socket?.id)
    })

    this.socket.on('disconnect', (reason) => {
      console.log('❌ Socket.io disconnected:', reason)
    })

    this.socket.on('connect_error', (error) => {
      console.error('🔴 Socket.io connection error:', error.message)
    })

    this.socket.on('connected', (data) => {
      console.log('✅ Server confirmation:', data)
    })
  }

  /**
   * Отключение
   */
  disconnect() {
    if (this.socket) {
      this.socket.disconnect()
      this.socket = null
    }
  }

  /**
   * Получение инстанса сокета
   */
  getSocket(): Socket | null {
    return this.socket
  }

  /**
   * Отправка события typing_start
   */
  emitTypingStart(chatId: string) {
    this.socket?.emit('typing_start', { chatId })
  }

  /**
   * Отправка события typing_stop
   */
  emitTypingStop(chatId: string) {
    this.socket?.emit('typing_stop', { chatId })
  }

  /**
   * Подтверждение доставки
   */
  emitMessageDelivered(messageId: string, toUsername: string) {
    this.socket?.emit('message_delivered', { messageId, toUsername })
  }

  /**
   * Подтверждение прочтения
   */
  emitMessageRead(messageId: string, toUsername: string) {
    this.socket?.emit('message_read', { messageId, toUsername })
  }

  /**
   * Подписка на новые сообщения
   */
  onNewMessage(callback: (data: any) => void) {
    this.socket?.on('new_message', callback)
  }

  /**
   * Отписка от новых сообщений
   */
  offNewMessage(callback: (data: any) => void) {
    this.socket?.off('new_message', callback)
  }

  /**
   * Подписка на typing
   */
  onUserTyping(callback: (data: { username: string; chatId: string }) => void) {
    this.socket?.on('user_typing', callback)
  }

  /**
   * Отписка от typing
   */
  offUserTyping(callback: (data: { username: string; chatId: string }) => void) {
    this.socket?.off('user_typing', callback)
  }

  /**
   * Подписка на stopped typing
   */
  onUserStoppedTyping(callback: (data: { username: string; chatId: string }) => void) {
    this.socket?.on('user_stopped_typing', callback)
  }

  /**
   * Отписка от stopped typing
   */
  offUserStoppedTyping(callback: (data: { username: string; chatId: string }) => void) {
    this.socket?.off('user_stopped_typing', callback)
  }

  /**
   * Подписка на обновление статуса сообщения
   */
  onMessageStatusUpdate(callback: (data: { messageId: string; status: string }) => void) {
    this.socket?.on('message_status_update', callback)
  }

  /**
   * Отписка от обновления статуса
   */
  offMessageStatusUpdate(callback: (data: { messageId: string; status: string }) => void) {
    this.socket?.off('message_status_update', callback)
  }

  /**
   * Подписка на обновление списка сессий
   */
  onSessionsUpdated(callback: () => void) {
    this.socket?.on('sessions:updated', callback)
  }

  /**
   * Отписка от обновления списка сессий
   */
  offSessionsUpdated(callback: () => void) {
    this.socket?.off('sessions:updated', callback)
  }

  /**
   * Подписка на завершение сессии
   */
  onSessionTerminated(callback: (data: { sessionId: string; message: string }) => void) {
    this.socket?.on('session:terminated', callback)
  }

  /**
   * Отписка от завершения сессии
   */
  offSessionTerminated(callback: (data: { sessionId: string; message: string }) => void) {
    this.socket?.off('session:terminated', callback)
  }
}

export const socketService = new SocketService()