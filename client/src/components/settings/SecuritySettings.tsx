import { useState, useEffect } from 'react'
import { Shield, Monitor, Trash2, LogOut, RefreshCw } from 'lucide-react'
import { apiService } from '@/services/api.service'
import './SecuritySettings.css'

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

export function SecuritySettings() {
  const [sessions, setSessions] = useState<Session[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState('')

  // Загрузка сессий
  const loadSessions = async () => {
    setIsLoading(true)
    setError('')

    try {
      const response = await apiService.getSessions()

      if (response.success && response.sessions) {
        setSessions(response.sessions)
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
    loadSessions()
  }, [])

  // Удаление конкретной сессии
  const handleDeleteSession = async (sessionId: string) => {
    if (!confirm('Are you sure you want to terminate this session?')) {
      return
    }

    try {
      const response = await apiService.deleteSession(sessionId)

      if (response.success) {
        // Обновляем список
        setSessions(sessions.filter(s => s.id !== sessionId))
      } else {
        setError(response.error || 'Failed to delete session')
      }
    } catch (error) {
      setError('Network error')
    }
  }

  // Выход со всех других устройств
  const handleDeleteOtherSessions = async () => {
    if (!confirm('Are you sure you want to sign out from all other devices?')) {
      return
    }

    try {
      const response = await apiService.deleteOtherSessions()

      if (response.success) {
        // Перезагружаем список
        loadSessions()
      } else {
        setError(response.error || 'Failed to delete sessions')
      }
    } catch (error) {
      setError('Network error')
    }
  }

  // Форматирование даты
  const formatDate = (dateString: string) => {
    const date = new Date(dateString)
    const now = new Date()
    const diff = now.getTime() - date.getTime()

    const minutes = Math.floor(diff / 60000)
    const hours = Math.floor(diff / 3600000)
    const days = Math.floor(diff / 86400000)

    if (minutes < 1) return 'Just now'
    if (minutes < 60) return `${minutes} min ago`
    if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`
    if (days < 7) return `${days} day${days > 1 ? 's' : ''} ago`

    return date.toLocaleDateString()
  }

  // Иконка устройства
  const getDeviceIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case 'desktop':
        return <Monitor size={20} />
      case 'mobile':
        return <Shield size={20} />
      default:
        return <Monitor size={20} />
    }
  }

  return (
    <div className="security-settings">
      <h3 className="settings-section-title">Security Settings</h3>

      {/* Active Sessions */}
      <div className="settings-block">
        <div className="settings-block-header">
          <h4>Active Sessions</h4>
          <button
            className="settings-btn settings-btn-icon"
            onClick={loadSessions}
            disabled={isLoading}
          >
            <RefreshCw size={16} className={isLoading ? 'spinning' : ''} />
          </button>
        </div>

        <div className="settings-block-content">
          {error && (
            <div className="security-error">{error}</div>
          )}

          {isLoading ? (
            <div className="security-loading">Loading sessions...</div>
          ) : sessions.length === 0 ? (
            <div className="security-empty">No active sessions</div>
          ) : (
            <>
              <div className="sessions-list">
                {sessions.map((session) => (
                  <div
                    key={session.id}
                    className={`session-item ${session.is_current ? 'current' : ''}`}
                  >
                    <div className="session-icon">
                      {getDeviceIcon(session.device_info?.type || 'desktop')}
                    </div>

                    <div className="session-info">
                      <div className="session-name">
                        {session.device_info?.name || 'Unknown Device'}
                        {session.is_current && (
                          <span className="session-badge">Current</span>
                        )}
                      </div>
                      <div className="session-details">
                        <span>{session.device_info?.os || 'Unknown OS'}</span>
                        <span className="session-separator">•</span>
                        <span>{session.ip_address}</span>
                      </div>
                      <div className="session-time">
                        Last active: {formatDate(session.last_active)}
                      </div>
                    </div>

                    {!session.is_current && (
                      <button
                        className="session-delete"
                        onClick={() => handleDeleteSession(session.id)}
                        title="Terminate session"
                      >
                        <Trash2 size={18} />
                      </button>
                    )}
                  </div>
                ))}
              </div>

              {sessions.filter(s => !s.is_current).length > 0 && (
                <div className="sessions-actions">
                  <button
                    className="settings-btn settings-btn-danger"
                    onClick={handleDeleteOtherSessions}
                  >
                    <LogOut size={16} />
                    Sign Out All Other Devices
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}