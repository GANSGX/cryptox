import { User, Shield, Lock, Bell, Palette } from 'lucide-react'
import type { SettingsSection } from './SettingsModal'

interface SettingsSidebarProps {
  activeSection: SettingsSection
  onSectionChange: (section: SettingsSection) => void
}

export function SettingsSidebar({ activeSection, onSectionChange }: SettingsSidebarProps) {
  const sections: { id: SettingsSection; label: string; icon: any }[] = [
    { id: 'account', label: 'Account', icon: User },
    { id: 'security', label: 'Security', icon: Shield },
    { id: 'privacy', label: 'Privacy', icon: Lock },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'appearance', label: 'Appearance', icon: Palette },
  ]

  return (
    <div className="settings-sidebar">
      {sections.map((section) => {
        const Icon = section.icon
        return (
          <button
            key={section.id}
            className={`settings-sidebar-item ${activeSection === section.id ? 'active' : ''}`}
            onClick={() => onSectionChange(section.id)}
          >
            <Icon size={20} />
            <span>{section.label}</span>
          </button>
        )
      })}
    </div>
  )
}