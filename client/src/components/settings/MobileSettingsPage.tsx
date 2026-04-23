import { useState } from "react";
import {
  User,
  ShieldCheck,
  Lock,
  Bell,
  Palette,
  CaretRight,
  CaretLeft,
} from "@phosphor-icons/react";
import { AccountSettings } from "./AccountSettings";
import { SecuritySettings } from "./SecuritySettings";
import type { SettingsSection } from "./SettingsModal";
import "./MobileSettingsPage.css";

const SECTIONS: {
  id: SettingsSection;
  label: string;
  icon: typeof User;
  color: string;
  bg: string;
}[] = [
  {
    id: "account",
    label: "Account",
    icon: User,
    color: "#4CC9F0",
    bg: "rgba(76,201,240,0.15)",
  },
  {
    id: "security",
    label: "Security",
    icon: ShieldCheck,
    color: "#34C759",
    bg: "rgba(52,199,89,0.15)",
  },
  {
    id: "privacy",
    label: "Privacy",
    icon: Lock,
    color: "#BF5AF2",
    bg: "rgba(191,90,242,0.15)",
  },
  {
    id: "notifications",
    label: "Notifications",
    icon: Bell,
    color: "#FF9F0A",
    bg: "rgba(255,159,10,0.15)",
  },
  {
    id: "appearance",
    label: "Appearance",
    icon: Palette,
    color: "#FF6B6B",
    bg: "rgba(255,107,107,0.15)",
  },
];

export function MobileSettingsPage() {
  const [section, setSection] = useState<SettingsSection | null>(null);

  const renderSection = () => {
    switch (section) {
      case "account":
        return <AccountSettings />;
      case "security":
        return <SecuritySettings />;
      default:
        return (
          <p
            style={{
              padding: 32,
              color: "rgba(255,255,255,0.4)",
              textAlign: "center",
            }}
          >
            Coming soon
          </p>
        );
    }
  };

  return (
    <div className="mobile-settings-page">
      {/* ── Список разделов ── */}
      <div className={`msp-list${section ? " msp-list--hidden" : ""}`}>
        <h1 className="msp-title">Settings</h1>

        <div className="msp-group">
          {SECTIONS.map(({ id, label, icon: Icon, color, bg }, i) => (
            <button
              key={id}
              className="msp-row"
              onClick={() => setSection(id)}
              style={
                { "--row-color": color, "--row-bg": bg } as React.CSSProperties
              }
            >
              <span className="msp-row-icon">
                <Icon size={19} weight="bold" />
              </span>
              <span className="msp-row-label">{label}</span>
              {i < SECTIONS.length - 1 && <span className="msp-row-sep" />}
              <CaretRight size={15} className="msp-row-chevron" />
            </button>
          ))}
        </div>
      </div>

      {/* ── Открытый раздел ── */}
      <div className={`msp-section${section ? " msp-section--visible" : ""}`}>
        <div className="msp-section-header">
          <button className="msp-back" onClick={() => setSection(null)}>
            <CaretLeft size={20} />
            <span>Settings</span>
          </button>
          <h2 className="msp-section-title">
            {SECTIONS.find((s) => s.id === section)?.label}
          </h2>
        </div>

        <div className="msp-section-body">{renderSection()}</div>
      </div>
    </div>
  );
}
