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

// Типы для подтверждения email
export interface SendVerificationCodeRequest {
  username: string
}

export interface VerifyEmailRequest {
  username: string
  code: string
}

export interface VerifyEmailResponse {
  message: string
  email_verified: boolean
}

// Типы для поиска пользователей
export interface SearchUsersQuery {
  q: string // query string
}

export interface UserSearchResult {
  username: string
  avatar_path: string | null
  bio: string | null
  email_verified: boolean
}

export interface SearchUsersResponse {
  users: UserSearchResult[]
  count: number
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

export interface GetMessagesQuery {
  limit?: number
  offset?: number
}

export interface GetMessagesResponse {
  messages: Array<{
    id: string
    sender_username: string
    recipient_username: string
    encrypted_content: string
    message_type: string
    created_at: string
    read_at: string | null
  }>
  total: number
  has_more: boolean
}