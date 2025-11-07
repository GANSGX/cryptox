import { useState } from 'react'
import { Mail, CheckCircle, XCircle, Edit2 } from 'lucide-react'
import { useAuthStore } from '@/store/authStore'
import { ChangeEmailModal } from './ChangeEmailModal'
import { VerifyEmailModal } from './VerifyEmailModal'
import './AccountSettings.css'

export function AccountSettings() {
  const { user, checkAuth } = useAuthStore()
  const [showChangeEmail, setShowChangeEmail] = useState(false)
  const [showVerifyEmail, setShowVerifyEmail] = useState(false)

  const isEmailVerified = user?.email_verified || false

  const handleEmailChanged = () => {
    // Обновляем данные пользователя после смены email
    checkAuth()
  }

  const handleEmailVerified = () => {
    // Обновляем данные пользователя после верификации
    checkAuth()
  }

  return (
    <div className="account-settings">
      <h3 className="settings-section-title">Account Settings</h3>

      {/* Username Section */}
      <div className="settings-block">
        <div className="settings-block-header">
          <h4>Username</h4>
        </div>
        <div className="settings-block-content">
          <div className="settings-info-row">
            <span className="settings-label">Current username:</span>
            <span className="settings-value">@{user?.username}</span>
          </div>
        </div>
      </div>

      {/* Email Section */}
      <div className="settings-block">
        <div className="settings-block-header">
          <h4>Email Address</h4>
        </div>
        <div className="settings-block-content">
          <div className="settings-email-row">
            <div className="settings-email-info">
              <Mail size={20} className="settings-email-icon" />
              <div>
                <div className="settings-email-address">{user?.email}</div>
                <div className={`settings-email-status ${isEmailVerified ? 'verified' : 'unverified'}`}>
                  {isEmailVerified ? (
                    <>
                      <CheckCircle size={16} />
                      <span>Verified</span>
                    </>
                  ) : (
                    <>
                      <XCircle size={16} />
                      <span>Not verified</span>
                    </>
                  )}
                </div>
              </div>
            </div>

            <div className="settings-email-actions">
              {!isEmailVerified && (
                <button
                  className="settings-btn settings-btn-primary"
                  onClick={() => setShowVerifyEmail(true)}
                >
                  Verify Email
                </button>
              )}
              <button
                className="settings-btn settings-btn-secondary"
                onClick={() => setShowChangeEmail(true)}
              >
                <Edit2 size={16} />
                Change Email
              </button>
            </div>
          </div>

        </div>
      </div>

      {/* Change Email Modal */}
      <ChangeEmailModal
        isOpen={showChangeEmail}
        onClose={() => setShowChangeEmail(false)}
        onSuccess={handleEmailChanged}
      />

      {/* Verify Email Modal */}
      <VerifyEmailModal
        isOpen={showVerifyEmail}
        onClose={() => setShowVerifyEmail(false)}
        onSuccess={handleEmailVerified}
      />
    </div>
  )
}