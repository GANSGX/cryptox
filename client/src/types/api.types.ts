// Общие типы для API ответов
export interface ApiResponse<T = any> {
  success: boolean
  data?: T
  error?: string
  message?: string
}

// Типы для регистрации
export interface RegisterRequest {
  username: string
  email: string
  password: string
  public_key: string
}

export interface RegisterResponse {
  token: string
  user: {
    username: string
    email: string
    email_verified: boolean
    created_at: string
  }
}

// Типы для логина
export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  token: string
  user: {
    username: string
    email: string
    email_verified: boolean
    last_seen: string
  }
}

// Типы для сообщений
export interface SendMessageRequest {
  recipient_username: string
  encrypted_content: string
  message_type?: 'text' | 'image' | 'video' | 'file' | 'audio'
}

export interface SendMessageResponse {
  message_id: string
  chat_id: string
  created_at: string
  status: 'sent'
}

export interface GetMessagesResponse {
  messages: Message[]
  total: number
  has_more: boolean
}

export interface Message {
  id: string
  sender_username: string
  recipient_username: string
  encrypted_content: string
  message_type: string
  created_at: string
  read_at: string | null
}