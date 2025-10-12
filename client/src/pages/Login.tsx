import { useState, FormEvent, useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { Globe } from 'lucide-react'
import { useAuthStore } from '@/store/authStore'
import { isValidUsername, isValidPassword, isValidEmail } from '@/utils/crypto'
import LiquidEther from '@/components/ui/LiquidEther'

export function Login() {
  const { t, i18n } = useTranslation()
  const { login, register, isLoading, error, clearError } = useAuthStore()

  const backgroundColors = useMemo(() => ['#5227FF', '#FF9FFC', '#B19EEF'], [])

  const [isRegister, setIsRegister] = useState(false)
  const [isFlipping, setIsFlipping] = useState(false)
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

    const success = isRegister
      ? await register(formData.username, formData.email, formData.password)
      : await login(formData.username, formData.password)

    if (success) {
      console.log('Login/Register successful!')
    }
  }

  const toggleMode = () => {
    setIsFlipping(true)
    setTimeout(() => {
      setIsRegister(!isRegister)
      setFormData({ username: '', email: '', password: '' })
      setErrors({ username: '', email: '', password: '' })
      clearError()
      setIsFlipping(false)
    }, 300)
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
          mouseForce={25}         // ⬆️ Увеличили силу (было 15)
          cursorSize={80}        // ⬆️ Больше радиус кисти (было 80)
          autoDemo={true}
          autoSpeed={0.5}         // ⬆️ Быстрее движение (было 0.3)
          autoIntensity={1.7}     // ⬆️ Сильнее волны (было 1.5)
          resolution={0.5}        // ⬆️ Чуть лучше качество (было 0.5)
          autoResumeDelay={800}   // ⬇️ Быстрее возобновление (было 1000)
          autoRampDuration={0.5}  // ⬇️ Быстрее разгон (было 0.6)
        />
      </div>

      {/* Карточка логина */}
      <div className={`auth-card ${isFlipping ? 'flipping' : ''}`} style={{ position: 'relative', zIndex: 1 }}>
        {/* Logo */}
        <div className="auth-logo">
          <div className="logo-icon">🔮</div>
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
            {isRegister ? t('auth.registerError') : t('auth.loginError')}: {error}
          </div>
        )}

        {/* Form */}
        <form className="auth-form" onSubmit={handleSubmit}>
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

        {/* Footer */}
        <div className="auth-footer">
          {isRegister ? t('auth.haveAccount') : t('auth.noAccount')}{' '}
          <span className="auth-link" onClick={toggleMode}>
            {isRegister ? t('auth.login') : t('auth.register')}
          </span>
        </div>

        {!isRegister && (
          <div className="auth-footer" style={{ marginTop: '12px' }}>
            <span className="auth-link">{t('auth.forgotPassword')}</span>
          </div>
        )}
      </div>
    </div>
  )
}