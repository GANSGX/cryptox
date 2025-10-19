import { useState, useEffect } from 'react'
import { apiService } from '@/services/api.service'
import { socketService } from '@/services/socket.service'

interface Session {
  id: string
  device_info: {
    type: string
    name: string
    os: string
  }
  ip_address: string
  created_at: string
  last_active: string
  is_current: boolean
}

export function useSessions() {
  const [sessions, setSessions] = useState<Session[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')

  // Загрузка сессий
  const loadSessions = async () => {
    try {
      const response = await apiService.getSessions()

      if (response.success && response.sessions) {
        setSessions(response.sessions)
        setError('')
      } else {
        setError(response.error || 'Failed to load sessions')
      }
    } catch (error) {
      setError('Network error')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    console.log('🎯 useSessions: Component mounted, loading sessions')
    
    // Загружаем список при монтировании
    loadSessions()

    // WebSocket: обновление списка сессий
    const handleSessionsUpdated = () => {
      console.log('🔄 Sessions updated via Socket.IO - reloading...')
      loadSessions()
    }

    // Подписываемся только на sessions:updated
    socketService.onSessionsUpdated(handleSessionsUpdated)

    // Отписываемся при размонтировании
    return () => {
      console.log('🔌 useSessions: Cleaning up Socket.IO listener')
      socketService.offSessionsUpdated(handleSessionsUpdated)
    }
  }, [])  // ← ПУСТОЙ массив!

  return {
    sessions,
    isLoading,
    error,
    reload: loadSessions,
  }
}