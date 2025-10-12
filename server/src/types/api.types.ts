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