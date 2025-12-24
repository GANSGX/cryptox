import type {
  ApiResponse,
  RegisterRequest,
  RegisterResponse,
  LoginRequest,
  LoginResponse,
  SendMessageRequest,
  SendMessageResponse,
  GetMessagesResponse,
  ApproveDeviceRequest,
  ApproveDeviceResponse,
  RejectDeviceRequest,
  VerifyDeviceCodeRequest,
  VerifyDeviceCodeResponse,
} from "@/types/api.types";

const API_URL = "/api";

class ApiService {
  public readonly API_URL = API_URL;
  private token: string | null = null;

  /**
   * Установка токена
   */
  setToken(token: string) {
    this.token = token;
    localStorage.setItem("token", token);
  }

  /**
   * Получение токена
   */
  getToken(): string | null {
    if (!this.token) {
      this.token = localStorage.getItem("token");
    }
    return this.token;
  }

  /**
   * Удаление токена
   */
  clearToken() {
    this.token = null;
    localStorage.removeItem("token");
  }

  /**
   * Базовый fetch с обработкой ошибок
   */
  private async request<T>(
    endpoint: string,
    options: RequestInit = {},
  ): Promise<ApiResponse<T>> {
    const token = this.getToken();

    const headers: Record<string, string> = {
      ...(options.headers as Record<string, string>),
    };

    // Добавляем Content-Type только если есть body
    if (options.body) {
      headers["Content-Type"] = "application/json";
    }

    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    try {
      const response = await fetch(`${API_URL}${endpoint}`, {
        ...options,
        headers,
      });

      const data = await response.json();

      if (!response.ok) {
        return {
          success: false,
          error: data.error || "Request failed",
        };
      }

      return data;
    } catch (err) {
      console.error("API Error:", err);
      return {
        success: false,
        error: "Network error",
      };
    }
  }

  /**
   * Регистрация
   */
  async register(
    data: RegisterRequest,
  ): Promise<ApiResponse<RegisterResponse>> {
    return this.request<RegisterResponse>("/auth/register", {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  /**
   * Логин
   */
  async login(data: LoginRequest): Promise<ApiResponse<LoginResponse>> {
    return this.request<LoginResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  /**
   * Выход (удаление сессии на сервере)
   */
  async logout(): Promise<ApiResponse> {
    return this.request("/auth/logout", {
      method: "POST",
    });
  }

  /**
   * Проверка авторизации
   */
  async me(): Promise<
    ApiResponse<{
      username: string;
      email: string;
      email_verified: boolean;
      status: string | null;
      birthday: string | null;
      avatar_path: string | null;
      status_privacy: string;
      online_privacy: string;
      typing_privacy: string;
    }>
  > {
    return this.request("/me");
  }

  /**
   * Поиск пользователей
   */
  async searchUsers(query: string): Promise<
    ApiResponse<{
      users: Array<{
        username: string;
        avatar_path: string | null;
        bio: string | null;
      }>;
      count: number;
    }>
  > {
    return this.request(`/users/search?q=${encodeURIComponent(query)}`);
  }

  /**
   * Отправка сообщения
   */
  async sendMessage(
    data: SendMessageRequest,
  ): Promise<ApiResponse<SendMessageResponse>> {
    return this.request<SendMessageResponse>("/messages", {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  /**
   * Получение истории чата
   */
  async getMessages(
    username: string,
    limit: number = 50,
    offset: number = 0,
  ): Promise<ApiResponse<GetMessagesResponse>> {
    return this.request<GetMessagesResponse>(
      `/messages/${username}?limit=${limit}&offset=${offset}`,
    );
  }

  /**
   * Пометить чат как прочитанный
   */
  async markChatAsRead(username: string): Promise<ApiResponse> {
    return this.request(`/messages/chat/${username}/read`, {
      method: "PATCH",
    });
  }

  /**
   * Получить количество непрочитанных
   */
  async getUnreadCount(
    username: string,
  ): Promise<ApiResponse<{ count: number }>> {
    return this.request<{ count: number }>(`/messages/chat/${username}/unread`);
  }

  /**
   * Проверка пароля и отправка кода на текущую почту
   */
  async verifyPasswordAndSendCode(
    username: string,
    password: string,
  ): Promise<ApiResponse> {
    return this.request("/auth/verify-password-send-code", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
  }

  /**
   * Проверка кода с текущей почты
   */
  async verifyCurrentEmailCode(
    username: string,
    code: string,
  ): Promise<ApiResponse> {
    return this.request("/auth/verify-current-email-code", {
      method: "POST",
      body: JSON.stringify({ username, code }),
    });
  }

  /**
   * Изменение email
   */
  async changeEmail(username: string, newEmail: string): Promise<ApiResponse> {
    return this.request("/auth/change-email", {
      method: "POST",
      body: JSON.stringify({ username, new_email: newEmail }),
    });
  }

  /**
   * Отправка кода верификации на email
   */
  async sendVerificationCode(username: string): Promise<ApiResponse> {
    return this.request("/auth/send-verification-code", {
      method: "POST",
      body: JSON.stringify({ username }),
    });
  }

  /**
   * Проверка кода и подтверждение email
   */
  async verifyEmail(username: string, code: string): Promise<ApiResponse> {
    return this.request("/auth/verify-email", {
      method: "POST",
      body: JSON.stringify({ username, code }),
    });
  }

  /**
   * Получить список активных сессий
   */
  async getSessions(): Promise<{
    success: boolean;
    sessions: Array<{
      id: string;
      device_info: Record<string, unknown>;
      ip_address: string;
      is_primary: boolean;
      is_current: boolean;
      seconds_ago: number;
      created_at: string;
      last_active: string;
    }>;
    error?: string;
  }> {
    const token = this.getToken();

    try {
      const response = await fetch(`${API_URL}/sessions`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const data = await response.json();

      if (!response.ok) {
        return {
          success: false,
          sessions: [],
          error: data.error || "Failed to get sessions",
        };
      }

      return data;
    } catch (err) {
      console.error("API Error:", err);
      return {
        success: false,
        sessions: [],
        error: "Network error",
      };
    }
  }

  /**
   * Удалить конкретную сессию
   */
  async deleteSession(sessionId: string): Promise<ApiResponse> {
    return this.request(`/sessions/${sessionId}`, {
      method: "DELETE",
    });
  }

  /**
   * Выйти со всех других устройств
   */
  async deleteOtherSessions(): Promise<ApiResponse<{ count: number }>> {
    return this.request<{ count: number }>("/sessions/others", {
      method: "DELETE",
    });
  }

  /**
   * Запрос на восстановление пароля (по email)
   */
  async forgotPassword(email: string): Promise<ApiResponse> {
    return this.request("/auth/forgot-password", {
      method: "POST",
      body: JSON.stringify({ email }),
    });
  }

  /**
   * Сброс пароля по токену из email
   */
  async resetPassword(
    token: string,
    newPassword: string,
  ): Promise<ApiResponse> {
    return this.request("/auth/reset-password", {
      method: "POST",
      body: JSON.stringify({ token, newPassword }),
    });
  }

  /**
   * Смена пароля (требует аутентификации)
   */
  async changePassword(
    currentPassword: string,
    newPassword: string,
  ): Promise<ApiResponse> {
    return this.request("/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ currentPassword, newPassword }),
    });
  }

  // ===== DEVICE APPROVAL METHODS =====

  /**
   * Одобрить новое устройство (primary device)
   */
  async approveDevice(
    data: ApproveDeviceRequest,
  ): Promise<ApiResponse<ApproveDeviceResponse>> {
    return this.request<ApproveDeviceResponse>("/auth/approve-device", {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  /**
   * Отклонить новое устройство (primary device)
   */
  async rejectDevice(data: RejectDeviceRequest): Promise<ApiResponse> {
    return this.request("/auth/reject-device", {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  /**
   * Проверить 6-значный код (новое устройство)
   */
  async verifyDeviceCode(
    data: VerifyDeviceCodeRequest,
  ): Promise<ApiResponse<VerifyDeviceCodeResponse>> {
    return this.request<VerifyDeviceCodeResponse>("/auth/verify-device-code", {
      method: "POST",
      body: JSON.stringify(data),
    });
  }

  /**
   * Редактирование сообщения
   */
  async editMessage(
    messageId: string,
    encrypted_content: string,
  ): Promise<ApiResponse> {
    return this.request(`/messages/${messageId}`, {
      method: "PATCH",
      body: JSON.stringify({ encrypted_content }),
    });
  }

  /**
   * Удаление сообщения
   * @param type - 'for_me' (удалить только у себя) или 'for_everyone' (удалить у всех)
   */
  async deleteMessage(
    messageId: string,
    type: "for_me" | "for_everyone",
  ): Promise<ApiResponse> {
    return this.request(`/messages/${messageId}?type=${type}`, {
      method: "DELETE",
    });
  }

  /**
   * Полная синхронизация контактов и истории (Telegram-style)
   * Возвращает список всех контактов с последним сообщением и unread count
   */
  async syncContacts(): Promise<
    ApiResponse<{
      contacts: Array<{
        username: string;
        lastMessage: string;
        lastMessageTime: string;
        unreadCount: number;
        isOnline?: boolean;
        avatar_path?: string | null;
      }>;
    }>
  > {
    return this.request("/messages/sync");
  }

  /**
   * Обновление профиля пользователя
   */
  async updateProfile(data: {
    status?: string;
    birthday?: string | null;
    avatar_path?: string | null;
    status_privacy?: "everyone" | "chats" | "friends" | "nobody";
    online_privacy?: "everyone" | "chats" | "friends" | "nobody";
    typing_privacy?: "everyone" | "chats" | "friends" | "nobody";
  }): Promise<
    ApiResponse<{
      username: string;
      email: string;
      email_verified: boolean;
      status: string | null;
      birthday: string | null;
      avatar_path: string | null;
      status_privacy: string;
      online_privacy: string;
      typing_privacy: string;
    }>
  > {
    return this.request("/profile", {
      method: "PATCH",
      body: JSON.stringify(data),
    });
  }

  /**
   * Загрузка аватарки
   */
  async uploadAvatar(file: File): Promise<
    ApiResponse<{
      avatar_path: string;
    }>
  > {
    const token = this.getToken();
    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch(`${API_URL}/upload-avatar`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        return {
          success: false,
          error: data.error || "Upload failed",
        };
      }

      return data;
    } catch (err) {
      console.error("Upload error:", err);
      return {
        success: false,
        error: "Network error",
      };
    }
  }

  /**
   * Загрузка фото в галерею профиля
   */
  async uploadProfilePhoto(file: File): Promise<
    ApiResponse<{
      id: string;
      photo_path: string;
      is_primary: boolean;
      position: number;
    }>
  > {
    const token = this.getToken();
    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch(`${API_URL}/profile/photos`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        return {
          success: false,
          error: data.error || "Upload failed",
        };
      }

      return data;
    } catch (err) {
      console.error("Upload error:", err);
      return {
        success: false,
        error: "Network error",
      };
    }
  }

  /**
   * Получить все фото профиля
   */
  async getProfilePhotos(): Promise<
    ApiResponse<{
      photos: Array<{
        id: string;
        photo_path: string;
        is_primary: boolean;
        position: number;
        created_at: string;
      }>;
    }>
  > {
    return this.request("/profile/photos");
  }

  /**
   * Удалить фото из галереи
   */
  async deleteProfilePhoto(photoId: string): Promise<ApiResponse> {
    return this.request(`/profile/photos/${photoId}`, {
      method: "DELETE",
    });
  }

  /**
   * Установить фото как основное
   */
  async setPrimaryPhoto(
    photoId: string,
  ): Promise<ApiResponse<{ photo_path: string }>> {
    return this.request<{ photo_path: string }>(
      `/profile/photos/${photoId}/set-primary`,
      {
        method: "PATCH",
      },
    );
  }
}

export const apiService = new ApiService();
