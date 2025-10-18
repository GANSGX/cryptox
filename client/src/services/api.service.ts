import type {
  ApiResponse,
  RegisterRequest,
  RegisterResponse,
  LoginRequest,
  LoginResponse,
  SendMessageRequest,
  SendMessageResponse,
  GetMessagesResponse,
} from '@/types/api.types'

const API_URL = '/api'

class ApiService {
  private token: string | null = null

  /**
   * Установка токена
   */
  setToken(token: string) {
    this.token = token
    localStorage.setItem('token', token)
  }

  /**
   * Получение токена
   */
  getToken(): string | null {
    if (!this.token) {
      this.token = localStorage.getItem('token')
    }
    return this.token
  }

  /**
   * Удаление токена
   */
  clearToken() {
    this.token = null
    localStorage.removeItem('token')
  }

  /**
   * Базовый fetch с обработкой ошибок
   */
  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    const token = this.getToken()

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    }

    if (token) {
      headers['Authorization'] = `Bearer ${token}`
    }

    try {
      const response = await fetch(`${API_URL}${endpoint}`, {
        ...options,
        headers,
      })

      const data = await response.json()

      if (!response.ok) {
        return {
          success: false,
          error: data.error || 'Request failed',
        }
      }

      return data
    } catch (error) {
      console.error('API Error:', error)
      return {
        success: false,
        error: 'Network error',
      }
    }
  }

  /**
   * Регистрация
   */
  async register(data: RegisterRequest): Promise<ApiResponse<RegisterResponse>> {
    return this.request<RegisterResponse>('/auth/register', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  }

  /**
   * Логин
   */
  async login(data: LoginRequest): Promise<ApiResponse<LoginResponse>> {
    return this.request<LoginResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  }

  /**
   * Проверка авторизации
   */
  async me(): Promise<ApiResponse<{ username: string; email: string; email_verified: boolean }>> {
    return this.request('/me')
  }

  /**
   * Поиск пользователей
   */
  async searchUsers(query: string): Promise<ApiResponse<{ users: any[]; count: number }>> {
    return this.request(`/users/search?q=${encodeURIComponent(query)}`)
  }

  /**
   * Отправка сообщения
   */
  async sendMessage(data: SendMessageRequest): Promise<ApiResponse<SendMessageResponse>> {
    return this.request<SendMessageResponse>('/messages', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  }

  /**
   * Получение истории чата
   */
  async getMessages(
    username: string,
    limit: number = 50,
    offset: number = 0
  ): Promise<ApiResponse<GetMessagesResponse>> {
    return this.request<GetMessagesResponse>(
      `/messages/${username}?limit=${limit}&offset=${offset}`
    )
  }

  /**
   * Пометить чат как прочитанный
   */
  async markChatAsRead(username: string): Promise<ApiResponse> {
    return this.request(`/messages/chat/${username}/read`, {
      method: 'PATCH',
    })
  }

  /**
   * Получить количество непрочитанных
   */
  async getUnreadCount(username: string): Promise<ApiResponse<{ count: number }>> {
    return this.request<{ count: number }>(`/messages/chat/${username}/unread`)
  }

  /**
   * Проверка пароля и отправка кода на текущую почту
   */
  async verifyPasswordAndSendCode(username: string, password: string): Promise<ApiResponse> {
    return this.request('/auth/verify-password-send-code', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    })
  }

  /**
   * Проверка кода с текущей почты
   */
  async verifyCurrentEmailCode(username: string, code: string): Promise<ApiResponse> {
    return this.request('/auth/verify-current-email-code', {
      method: 'POST',
      body: JSON.stringify({ username, code }),
    })
  }

  /**
   * Изменение email
   */
  async changeEmail(username: string, newEmail: string): Promise<ApiResponse> {
    return this.request('/auth/change-email', {
      method: 'POST',
      body: JSON.stringify({ username, new_email: newEmail }),
    })
  }
}

export const apiService = new ApiService()