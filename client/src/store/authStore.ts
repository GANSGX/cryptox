import { create } from 'zustand'
import { apiService } from '@/services/api.service'
import { socketService } from '@/services/socket.service'
import { cryptoService } from '@/services/crypto.service'
import { fingerprintService } from '@/services/fingerprint.service'
import type { User } from '@/types/user.types'

interface AuthState {
  user: User | null
  token: string | null
  isLoading: boolean
  error: string | null

  // Actions
  login: (username: string, password: string) => Promise<boolean>
  register: (username: string, email: string, password: string) => Promise<boolean>
  logout: () => Promise<void>
  checkAuth: () => Promise<void>
  clearError: () => void
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  token: null,
  isLoading: false,
  error: null,

  /**
   * Логин
   */
  login: async (username: string, password: string) => {
    set({ isLoading: true, error: null })

    try {
      // Генерируем fingerprint устройства
      const deviceFingerprint = await fingerprintService.getFingerprint()

      const response = await apiService.login({ username, password, deviceFingerprint })

      if (!response.success || !response.data) {
        set({ error: response.error || 'Login failed', isLoading: false })
        return false
      }

      const { token, user } = response.data

      // Сохраняем токен
      apiService.setToken(token)

      // Подключаем Socket.io
      socketService.connect(token)

      // Загружаем session keys
      cryptoService.loadSessionKeys()

      set({
        user: {
          username: user.username,
          email: user.email,
          email_verified: user.email_verified || false,
        },
        token,
        isLoading: false,
        error: null,
      })

      return true
    } catch (error) {
      set({ error: 'Network error', isLoading: false })
      return false
    }
  },

  /**
   * Регистрация
   */
  register: async (username: string, email: string, password: string) => {
    set({ isLoading: true, error: null })

    try {
      // Генерируем fingerprint устройства
      const deviceFingerprint = await fingerprintService.getFingerprint()

      // Для MVP используем заглушку для public_key
      const public_key = `${username}_public_key_${Date.now()}`

      const response = await apiService.register({
        username,
        email,
        password,
        public_key,
        deviceFingerprint,
      })

      if (!response.success || !response.data) {
        set({ error: response.error || 'Registration failed', isLoading: false })
        return false
      }

      const { token, user } = response.data

      // Сохраняем токен
      apiService.setToken(token)

      // Подключаем Socket.io
      socketService.connect(token)

      set({
        user: {
          username: user.username,
          email: user.email,
          email_verified: user.email_verified || false,
        },
        token,
        isLoading: false,
        error: null,
      })

      return true
    } catch (error) {
      set({ error: 'Network error', isLoading: false })
      return false
    }
  },

  /**
   * Выход
   */
  logout: async () => {
    // Сначала вызываем API для удаления сессии на сервере
    try {
      await apiService.logout()
    } catch (error) {
      // Игнорируем ошибки, все равно удаляем локальные данные
      console.error('Logout error:', error)
    }

    // Затем очищаем локальные данные
    apiService.clearToken()
    socketService.disconnect()
    cryptoService.clearSessionKeys()

    localStorage.removeItem('email_verify_dismissed')

    set({
      user: null,
      token: null,
      error: null,
    })
  },

  /**
   * Проверка авторизации (при загрузке страницы)
   */
  checkAuth: async () => {
    const token = apiService.getToken()

    if (!token) {
      set({ user: null, token: null })
      return
    }

    set({ isLoading: true })

    try {
      const response = await apiService.me()

      if (!response.success || !response.data) {
        apiService.clearToken()
        set({ user: null, token: null, isLoading: false })
        return
      }

      // Подключаем Socket.io
      socketService.connect(token)

      // Загружаем session keys
      cryptoService.loadSessionKeys()

      set({
        user: {
          username: response.data.username,
          email: response.data.email,
          email_verified: response.data.email_verified || false,
        },
        token,
        isLoading: false,
      })
    } catch (error) {
      apiService.clearToken()
      set({ user: null, token: null, isLoading: false })
    }
  },

  /**
   * Очистка ошибки
   */
  clearError: () => set({ error: null }),
}))