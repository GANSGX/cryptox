import { X, AlertCircle, Shield, Key, Mail } from 'lucide-react'
import { useState, useEffect } from 'react'
import { useAuthStore } from '@/store/authStore'
import { VerifyEmailModal } from './VerifyEmailModal'
import './EmailVerificationBanner.css'

export function EmailVerificationBanner() {
  const { user } = useAuthStore()
  const [isVisible, setIsVisible] = useState(false)
  const [showVerifyModal, setShowVerifyModal] = useState(false)

  useEffect(() => {
    // Показываем баннер только если email не подтверждён
    if (user && !user.email_verified) {
      // Проверяем localStorage - когда пользователь нажал "Напомнить позже"
      const dismissedUntil = localStorage.getItem('email_verify_dismissed')

      if (dismissedUntil) {
        const dismissedTime = parseInt(dismissedUntil, 10)
        const now = Date.now()

        // Если прошло меньше сессии - не показываем
        if (now < dismissedTime) {
          return
        }
      }

      // Показываем баннер
      setIsVisible(true)
    }
  }, [user])

  if (!isVisible || !user || user.email_verified) {
    return null
  }

  const handleVerifyEmail = () => {
    setShowVerifyModal(true)
  }

  const handleRemindLater = () => {
    // Закрываем до конца сессии (до выхода из аккаунта)
    // При следующем логине баннер появится снова
    setIsVisible(false)
    // Сохраняем timestamp на 24 часа (опционально)
    localStorage.setItem('email_verify_dismissed', String(Date.now() + 86400000))
  }

  const handleClose = () => {
    handleRemindLater()
  }

  const handleVerifySuccess = () => {
    setShowVerifyModal(false)
    setIsVisible(false)
    // Удаляем флаг dismissal
    localStorage.removeItem('email_verify_dismissed')
  }

  return (
    <>
      <div className="email-banner-overlay" />
      
      <div className="email-verification-banner">
        <div className="email-banner-header">
          <AlertCircle size={24} className="email-banner-icon-warning" />
          <h3>Confirm Your Email</h3>
          <button className="email-banner-close" onClick={handleClose}>
            <X size={20} />
          </button>
        </div>

        <div className="email-banner-content">
          <p className="email-banner-description">
            Your email <strong>{user.email}</strong> is not verified. 
            Without verification, your account has limitations.
          </p>

          <div className="email-banner-limitations">
            <h4>⚠️ Current Limitations:</h4>
            <ul>
              <li>
                <Mail size={16} />
                <span><strong>Messages:</strong> Maximum 10 per hour</span>
              </li>
              <li>
                <Shield size={16} />
                <span><strong>Contacts:</strong> Maximum 5 new per day</span>
              </li>
              <li>
                <Key size={16} />
                <span><strong>Password Recovery:</strong> Unavailable</span>
              </li>
              <li>
                <Shield size={16} />
                <span><strong>Two-Factor Authentication:</strong> Unavailable</span>
              </li>
            </ul>
          </div>

          <div className="email-banner-benefits">
            <h4>✅ With Verified Email:</h4>
            <ul>
              <li>Unlimited messages and contacts</li>
              <li>Password recovery via email</li>
              <li>Enable Two-Factor Authentication</li>
              <li>Full account security</li>
              <li>Access to all features</li>
            </ul>
          </div>
        </div>

        <div className="email-banner-actions">
          <button
            className="email-banner-btn email-banner-btn-secondary"
            onClick={handleRemindLater}
          >
            Remind Me Later
          </button>
          <button
            className="email-banner-btn email-banner-btn-primary"
            onClick={handleVerifyEmail}
          >
            Verify Email
          </button>
        </div>
      </div>

      {/* Verify Email Modal */}
      <VerifyEmailModal 
        isOpen={showVerifyModal}
        onClose={() => setShowVerifyModal(false)}
        onSuccess={handleVerifySuccess}
      />
    </>
  )
}