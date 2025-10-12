import { useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from '@/store/authStore'
import { Login } from '@/pages/Login'
import { Chat } from '@/pages/Chat'
import '@/i18n/config'
import '@/styles/index.css'

function App() {
  const { user, checkAuth, isLoading } = useAuthStore()

  useEffect(() => {
    checkAuth()
  }, [checkAuth])

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