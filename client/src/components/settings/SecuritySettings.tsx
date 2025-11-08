import { Shield, Monitor, Trash2, LogOut } from 'lucide-react'
import { apiService } from '@/services/api.service'
import { useSessions } from '@/hooks/useSessions'
import './SecuritySettings.css'

export function SecuritySettings() {
  const { sessions, isLoading, error } = useSessions()

  // Удаление конкретной сессии
  const handleDeleteSession = async (sessionId: string) => {
    if (!confirm('Are you sure you want to terminate this session?')) {
      return
    }

    await apiService.deleteSession(sessionId)
    // Список обновится через WebSocket автоматически!
  }

  // Выход со всех других устройств
  const handleDeleteOtherSessions = async () => {
    if (!confirm('Are you sure you want to sign out from all other devices?')) {
      return
    }

    await apiService.deleteOtherSessions()
    // Список обновится через WebSocket автоматически!
  }

  // Форматирование времени (используем seconds_ago от сервера)
  const formatTimeAgo = (secondsAgo: number) => {
    if (secondsAgo < 0) {
      return 'Just now'
    }

    const minutes = Math.floor(secondsAgo / 60)
    const hours = Math.floor(secondsAgo / 3600)
    const days = Math.floor(secondsAgo / 86400)

    if (secondsAgo < 30) return 'Just now'
    if (minutes < 1) return 'Just now'
    if (minutes < 60) return `${minutes} min ago`
    if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`
    if (days < 7) return `${days} day${days > 1 ? 's' : ''} ago`
    if (days < 30) return `${days} day${days > 1 ? 's' : ''} ago`
    if (days < 365) {
      const months = Math.floor(days / 30)
      return `${months} month${months > 1 ? 's' : ''} ago`
    }

    const years = Math.floor(days / 365)
    return `${years} year${years > 1 ? 's' : ''} ago`
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
          <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
            Updates in real-time
          </div>
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
                        {session.is_primary && (
                          <span className="session-badge primary">Primary Device</span>
                        )}
                      </div>
                      <div className="session-details">
                        <span>{session.device_info?.os || 'Unknown OS'}</span>
                        <span className="session-separator">•</span>
                        <span>{session.ip_address}</span>
                      </div>
                      <div className="session-time">
                        Last active: {formatTimeAgo(session.seconds_ago)}
                      </div>
                    </div>

                    {!session.is_current && !session.is_primary && (
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