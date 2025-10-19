import { X } from 'lucide-react'
import { useState, useEffect } from 'react'
import { SettingsSidebar } from './SettingsSidebar'
import { AccountSettings } from './AccountSettings'
import { SecuritySettings } from './SecuritySettings'
import './SettingsModal.css'

interface SettingsModalProps {
  isOpen: boolean
  onClose: () => void
}

export type SettingsSection = 'account' | 'security' | 'privacy' | 'notifications' | 'appearance'

export function SettingsModal({ isOpen, onClose }: SettingsModalProps) {
  const [activeSection, setActiveSection] = useState<SettingsSection>('account')
  const [isMounted, setIsMounted] = useState(false)
  const [isAnimated, setIsAnimated] = useState(false)

  useEffect(() => {
    if (isOpen) {
      setIsMounted(true)
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          setIsAnimated(true)
        })
      })
    } else if (isMounted) {
      setIsAnimated(false)
      const timer = setTimeout(() => {
        setIsMounted(false)
      }, 300)
      return () => clearTimeout(timer)
    }
  }, [isOpen, isMounted])

  if (!isMounted) return null

  const renderContent = () => {
    switch (activeSection) {  // ← ИСПРАВЛЕНО: было activeTab
      case 'account':
        return <AccountSettings />
      case 'security':
        return <SecuritySettings />
      case 'privacy':
      case 'notifications':
      case 'appearance':
        return (
          <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-secondary)' }}>
            {activeSection.charAt(0).toUpperCase() + activeSection.slice(1)} Settings (Coming Soon)
          </div>
        )
      default:
        return null
    }
  }

  return (
    <>
      {/* Overlay */}
      <div
        className={`settings-overlay ${isAnimated ? 'visible' : ''}`}
        onClick={onClose}
      />

      {/* Modal */}
      <div className={`settings-modal ${isAnimated ? 'open' : ''}`}>
        {/* Header */}
        <div className="settings-header">
          <h2>Settings</h2>
          <button className="settings-close-button" onClick={onClose}>
            <X size={24} />
          </button>
        </div>

        {/* Content */}
        <div className="settings-content">
          {/* Sidebar */}
          <SettingsSidebar
            activeSection={activeSection}
            onSectionChange={setActiveSection}
          />

          {/* Main Content */}
          <div className="settings-main">
            {renderContent()}
          </div>
        </div>
      </div>
    </>
  )
}