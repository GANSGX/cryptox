import { useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from '@/store/authStore'
import { socketService } from '@/services/socket.service'
import { apiService } from '@/services/api.service'
import { Login } from '@/pages/Login'
import { Chat } from '@/pages/Chat'
import '@/i18n/config'
import '@/styles/index.css'

function App() {
  const { user, checkAuth, isLoading, logout } = useAuthStore()

  useEffect(() => {
    checkAuth()
  }, [checkAuth])

  // ГЛОБАЛЬНАЯ подписка на Socket.IO события
  useEffect(() => {
    if (!user) return

    console.log('🎯 App: Setting up global Socket.IO listeners for user:', user.username)

    // Глобальный обработчик: сессия завершена
    const handleSessionTerminated = async (data: { sessionId: string; message: string }) => {
      console.log('🚪 GLOBAL: Session terminated event received:', data.sessionId)
      
      try {
        // Проверяем список сессий
        const response = await apiService.getSessions()
        
        if (response.success && response.sessions) {
          const currentSession = response.sessions.find(s => s.is_current)
          
          // Если нашей текущей сессии нет в списке - нас выкинули!
          if (!currentSession) {
            console.log('❌ Current session not found - logging out!')
            alert(data.message)
            logout()
            window.location.href = '/login'
          } else {
            console.log('✅ Current session still active')
          }
        }
      } catch (error) {
        console.error('Error checking sessions after termination:', error)
      }
    }

    // Подписываемся на событие
    socketService.onSessionTerminated(handleSessionTerminated)

    // Отписываемся при размонтировании или выходе
    return () => {
      console.log('🔌 App: Cleaning up Socket.IO listeners')
      socketService.offSessionTerminated(handleSessionTerminated)
    }
  }, [user, logout])

  if (isLoading) {
    return (
      <div style={{ 
        minHeight: '100vh', 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'center' 
      }}>
        <div className="loading"></div>
      </div>
    )
  }

  return (
    <BrowserRouter>
      <Routes>
        <Route 
          path="/login" 
          element={user ? <Navigate to="/chat" replace /> : <Login />} 
        />
        <Route 
          path="/chat" 
          element={user ? <Chat /> : <Navigate to="/login" replace />} 
        />
        <Route 
          path="*" 
          element={<Navigate to={user ? "/chat" : "/login"} replace />} 
        />
      </Routes>
    </BrowserRouter>
  )
}

export default App