import { useState } from 'react'
import { Mail, CheckCircle, XCircle, Edit2 } from 'lucide-react'
import { useAuthStore } from '@/store/authStore'
import './AccountSettings.css'

export function AccountSettings() {
  const { user } = useAuthStore()
  const [showChangeEmail, setShowChangeEmail] = useState(false)

  const isEmailVerified = user?.email_verified || false

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
                <button className="settings-btn settings-btn-primary">
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

          {/* Verification Benefits */}
          {!isEmailVerified && (
            <div className="settings-info-banner">
              <div className="settings-info-banner-icon">ℹ️</div>
              <div className="settings-info-banner-content">
                <strong>Why verify your email?</strong>
                <ul>
                  <li>Recover your password if you forget it</li>
                  <li>Enable Two-Factor Authentication (2FA)</li>
                  <li>Receive important security notifications</li>
                  <li>Unlock all account features</li>
                </ul>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Change Email Modal - будет позже */}
      {showChangeEmail && (
        <div className="settings-info-banner">
          <p>Change Email flow - Coming in next step...</p>
          <button 
            className="settings-btn settings-btn-secondary"
            onClick={() => setShowChangeEmail(false)}
          >
            Close
          </button>
        </div>
      )}
    </div>
  )
}