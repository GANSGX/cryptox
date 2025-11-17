import { useState, FormEvent, useMemo, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { Globe } from 'lucide-react'
import { useAuthStore } from '@/store/authStore'
import { socketService } from '@/services/socket.service'
import { isValidUsername, isValidPassword, isValidEmail } from '@/utils/crypto'
import LiquidEther from '@/components/ui/LiquidEther'
import { ForgotPasswordModal } from '@/components/auth/ForgotPasswordModal'
import { VerificationCodeInput } from '@/components/auth/VerificationCodeInput'

export function Login() {
  const { t, i18n } = useTranslation()
  const navigate = useNavigate()
  const { login, register, isLoading, error, clearError, user, pendingApproval, verifyDeviceCode } =
    useAuthStore()

  const backgroundColors = useMemo(() => ['#5227FF', '#FF9FFC', '#B19EEF'], [])

  const [isRegister, setIsRegister] = useState(false)
  const [isTransitioning, setIsTransitioning] = useState(false)
  const [isForgotPasswordOpen, setIsForgotPasswordOpen] = useState(false)
  const [verificationCode, setVerificationCode] = useState('')
  const [rejectionError, setRejectionError] = useState('')
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
  })
  const [errors, setErrors] = useState({
    username: '',
    email: '',
    password: '',
  })

  // Автоматический редирект если уже залогинен
  useEffect(() => {
    if (user) {
      navigate('/chat', { replace: true })
    }
  }, [user, navigate])

  // Socket.IO подключение для отслеживания rejection (новое устройство)
  useEffect(() => {
    if (!pendingApproval) return

    console.log('🔌 Login: Connecting to Socket.IO for pending approval:', pendingApproval.pending_session_id)

    // Подключаемся к Socket.IO с pending_session_id
    socketService.connectForPendingApproval(pendingApproval.pending_session_id)

    console.log('🎧 Login: Listening for device:rejected event')

    const handleDeviceRejected = () => {
      console.log('❌ Device rejected by primary device')
      setRejectionError('Device approval was rejected. Please try again.')
      clearError()
      // Возвращаемся к форме логина через 3 секунды
      setTimeout(() => {
        window.location.reload()
      }, 3000)
    }

    socketService.on('device:rejected', handleDeviceRejected)

    return () => {
      socketService.off('device:rejected', handleDeviceRejected)
      socketService.disconnect()
    }
  }, [pendingApproval, clearError])

  const toggleLanguage = () => {
    const newLang = i18n.language === 'en' ? 'ru' : 'en'
    i18n.changeLanguage(newLang)
    localStorage.setItem('language', newLang)
  }

  const validate = () => {
    const newErrors = { username: '', email: '', password: '' }
    let isValid = true

    if (!isValidUsername(formData.username)) {
      newErrors.username = t('auth.usernameError')
      isValid = false
    }

    if (isRegister && !isValidEmail(formData.email)) {
      newErrors.email = t('auth.emailError')
      isValid = false
    }

    if (!isValidPassword(formData.password)) {
      newErrors.password = t('auth.passwordError')
      isValid = false
    }

    setErrors(newErrors)
    return isValid
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    clearError()

    if (!validate()) {
      return
    }

    if (isRegister) {
      const success = await register(formData.username, formData.email, formData.password)
      if (success) {
        navigate('/chat', { replace: true })
      }
    } else {
      const result = await login(formData.username, formData.password)
      if (result === true) {
        navigate('/chat', { replace: true })
      }
      // Если result === 'pending_approval', показываем UI для ввода кода
    }
  }

  const handleVerifyCode = async (e: FormEvent) => {
    e.preventDefault()

    if (verificationCode.length !== 6) {
      return
    }

    const success = await verifyDeviceCode(verificationCode)
    if (success) {
      navigate('/chat', { replace: true })
    }
  }

  const toggleMode = () => {
    setIsTransitioning(true)

    // Ждём полного исчезновения старых форм
    setTimeout(() => {
      setIsRegister(!isRegister)
      setFormData({ username: '', email: '', password: '' })
      setErrors({ username: '', email: '', password: '' })
      clearError()
      setIsTransitioning(false) // Сразу запускаем появление новых
    }, 600) // Меняем контент ПОСЛЕ полного исчезновения
  }

  return (
    <div className="auth-container">
      {/* Анимированный фон */}
      <div
        style={{
          position: 'fixed',
          top: 0,
          left: 0,
          width: '100%',
          height: '100%',
          zIndex: 0,
          pointerEvents: 'none',
        }}
      >
        <LiquidEther
          key="background"
          colors={backgroundColors}
          mouseForce={25}
          cursorSize={80}
          autoDemo={true}
          autoSpeed={0.5}
          autoIntensity={1.7}
          resolution={0.5}
          autoResumeDelay={800}
          autoRampDuration={0.5}
        />
      </div>

      {/* Карточка логина */}
      <div className="auth-card" style={{ position: 'relative', zIndex: 1 }}>
        {/* Logo */}
        <div className="auth-logo">
          <div className="logo-icon">
            <svg viewBox="0 0 24 24">
              <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z" />
            </svg>
          </div>
          <h1 className="logo-text">{t('common.appName')}</h1>
        </div>

        {/* Controls (Language only) */}
        <div className="auth-controls">
          <button className="control-button" onClick={toggleLanguage} title={t('common.language')}>
            <Globe size={18} />
            <span>{i18n.language.toUpperCase()}</span>
          </button>
        </div>

        {/* Title */}
        <h2 className="auth-title">{isRegister ? t('auth.register') : t('auth.login')}</h2>

        {/* Error Alert */}
        {error && (
          <div className="alert alert-error">
            {error}
          </div>
        )}

        {/* Device Approval: Ввод кода */}
        {pendingApproval ? (
          <div className="auth-form entering" style={{ textAlign: 'center' }}>
            <div style={{ marginBottom: '24px' }}>
              <h3 style={{ fontSize: '20px', marginBottom: '12px' }}>🔒 Device Approval Required</h3>
              <p style={{ color: '#888', fontSize: '14px' }}>
                Check your primary device for approval
              </p>
            </div>

            {rejectionError && (
              <div className="alert alert-error" style={{ marginBottom: '20px' }}>
                {rejectionError}
              </div>
            )}

            <form onSubmit={handleVerifyCode}>
              <VerificationCodeInput
                value={verificationCode}
                onChange={setVerificationCode}
                disabled={isLoading}
                autoFocus
              />

              <button
                type="submit"
                className="btn btn-primary"
                disabled={isLoading || verificationCode.length !== 6}
                style={{ marginTop: '12px' }}
              >
                {isLoading ? <span className="loading"></span> : 'Verify Code'}
              </button>
            </form>

            <div className="auth-footer" style={{ marginTop: '20px' }}>
              Waiting for approval...
            </div>
          </div>
        ) : (
          /* Обычная форма логина/регистрации */
          <form
            className={`auth-form ${isTransitioning ? 'exiting' : 'entering'}`}
            onSubmit={handleSubmit}
            key={isRegister ? 'register' : 'login'}
          >
            {/* Username */}
            <div className="form-group">
              <label className="form-label">{t('auth.username')}</label>
              <input
                type="text"
                className={`form-input ${errors.username ? 'error' : ''}`}
                value={formData.username}
                onChange={(e) => setFormData({ ...formData, username: e.target.value.toLowerCase() })}
                placeholder={t('auth.username')}
                disabled={isLoading}
                autoComplete="username"
              />
              {errors.username && <span className="form-error">{errors.username}</span>}
            </div>

            {/* Email (only for register) */}
            {isRegister && (
              <div className="form-group">
                <label className="form-label">{t('auth.email')}</label>
                <input
                  type="email"
                  className={`form-input ${errors.email ? 'error' : ''}`}
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value.toLowerCase() })}
                  placeholder={t('auth.email')}
                  disabled={isLoading}
                  autoComplete="email"
                />
                {errors.email && <span className="form-error">{errors.email}</span>}
              </div>
            )}

            {/* Password */}
            <div className="form-group">
              <label className="form-label">{t('auth.password')}</label>
              <input
                type="password"
                className={`form-input ${errors.password ? 'error' : ''}`}
                value={formData.password}
                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                placeholder={t('auth.password')}
                disabled={isLoading}
                autoComplete={isRegister ? 'new-password' : 'current-password'}
              />
              {errors.password && <span className="form-error">{errors.password}</span>}
            </div>

            {/* Submit Button */}
            <button type="submit" className="btn btn-primary" disabled={isLoading}>
              {isLoading ? (
                <span className="loading"></span>
              ) : isRegister ? (
                t('auth.registerButton')
              ) : (
                t('auth.loginButton')
              )}
            </button>
          </form>
        )}

        {/* Footer */}
        <div className="auth-footer">
          {isRegister ? t('auth.haveAccount') : t('auth.noAccount')}{' '}
          <span className="auth-link" onClick={toggleMode}>
            {isRegister ? t('auth.login') : t('auth.register')}
          </span>
        </div>

        {!isRegister && (
          <div className="auth-footer" style={{ marginTop: '12px' }}>
            <span className="auth-link" onClick={() => setIsForgotPasswordOpen(true)}>
              {t('auth.forgotPassword')}
            </span>
          </div>
        )}
      </div>

      {/* Forgot Password Modal */}
      <ForgotPasswordModal
        isOpen={isForgotPasswordOpen}
        onClose={() => setIsForgotPasswordOpen(false)}
      />
    </div>
  )
}