import {
  User,
  ShieldCheck,
  Lock,
  Bell,
  Palette,
  type Icon,
} from "@phosphor-icons/react";
import type { SettingsSection } from "./SettingsModal";

interface SettingsSidebarProps {
  activeSection: SettingsSection;
  onSectionChange: (section: SettingsSection) => void;
}

export function SettingsSidebar({
  activeSection,
  onSectionChange,
}: SettingsSidebarProps) {
  const sections: {
    id: SettingsSection;
    label: string;
    icon: Icon;
  }[] = [
    { id: "account", label: "Account", icon: User },
    { id: "security", label: "Security", icon: ShieldCheck },
    { id: "privacy", label: "Privacy", icon: Lock },
    { id: "notifications", label: "Notifications", icon: Bell },
    { id: "appearance", label: "Appearance", icon: Palette },
  ];

  return (
    <div className="settings-sidebar">
      <h2 className="settings-sidebar-title">Settings</h2>
      {sections.map((section) => {
        const Icon = section.icon;
        return (
          <button
            key={section.id}
            className={`settings-sidebar-item ${activeSection === section.id ? "active" : ""}`}
            onClick={() => onSectionChange(section.id)}
          >
            <Icon size={20} />
            <span>{section.label}</span>
          </button>
        );
      })}
    </div>
  );
}
