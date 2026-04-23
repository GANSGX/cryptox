import {
  X,
  CaretLeft,
  User,
  ShieldCheck,
  Lock,
  Bell,
  Palette,
  CaretRight,
} from "@phosphor-icons/react";
import { useState, useEffect } from "react";
import { SettingsSidebar } from "./SettingsSidebar";
import { AccountSettings } from "./AccountSettings";
import { SecuritySettings } from "./SecuritySettings";
import "./SettingsModal.css";

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export type SettingsSection =
  | "account"
  | "security"
  | "privacy"
  | "notifications"
  | "appearance";

const SECTIONS: { id: SettingsSection; label: string; icon: typeof User }[] = [
  { id: "account", label: "Account", icon: User },
  { id: "security", label: "Security", icon: ShieldCheck },
  { id: "privacy", label: "Privacy", icon: Lock },
  { id: "notifications", label: "Notifications", icon: Bell },
  { id: "appearance", label: "Appearance", icon: Palette },
];

const MOBILE_BP = 768;

export function SettingsModal({ isOpen, onClose }: SettingsModalProps) {
  const [activeSection, setActiveSection] =
    useState<SettingsSection>("account");
  const [isMounted, setIsMounted] = useState(false);
  const [isAnimated, setIsAnimated] = useState(false);
  const [isMobile, setIsMobile] = useState(window.innerWidth <= MOBILE_BP);
  // "list" = список разделов, "section" = открытый раздел
  const [mobileView, setMobileView] = useState<"list" | "section">("list");

  useEffect(() => {
    const onResize = () => setIsMobile(window.innerWidth <= MOBILE_BP);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  useEffect(() => {
    if (isOpen) {
      setMobileView("list"); // всегда открываем со списка
      setIsMounted(true);
      requestAnimationFrame(() =>
        requestAnimationFrame(() => setIsAnimated(true)),
      );
    } else if (isMounted) {
      setIsAnimated(false);
      const t = setTimeout(() => setIsMounted(false), 400);
      return () => clearTimeout(t);
    }
  }, [isOpen]);

  if (!isMounted) return null;

  const renderContent = () => {
    switch (activeSection) {
      case "account":
        return <AccountSettings />;
      case "security":
        return <SecuritySettings />;
      default:
        return (
          <div
            style={{
              padding: "40px",
              textAlign: "center",
              color: "var(--text-secondary)",
            }}
          >
            {SECTIONS.find((s) => s.id === activeSection)?.label} — Coming Soon
          </div>
        );
    }
  };

  const openSection = (id: SettingsSection) => {
    setActiveSection(id);
    setMobileView("section");
  };

  /* ── Мобильный рендер — две «страницы» ── */
  if (isMobile) {
    return (
      <>
        <div
          className={`settings-overlay ${isAnimated ? "visible" : ""}`}
          onClick={onClose}
        />

        <div
          className={`settings-modal settings-modal-mobile ${isAnimated ? "open" : ""}`}
        >
          {/* Страница 1: список разделов */}
          <div
            className={`sm-list-page${mobileView === "list" ? " sm-page-visible" : " sm-page-hidden-right"}`}
          >
            <div className="sm-topbar">
              <h2 className="sm-title">Settings</h2>
              <button className="sm-icon-btn" onClick={onClose}>
                <X size={20} />
              </button>
            </div>

            <div className="sm-list">
              {SECTIONS.map(({ id, label, icon: Icon }) => (
                <button
                  key={id}
                  className="sm-list-item"
                  onClick={() => openSection(id)}
                >
                  <span className="sm-list-icon">
                    <Icon size={20} />
                  </span>
                  <span className="sm-list-label">{label}</span>
                  <CaretRight size={16} className="sm-list-chevron" />
                </button>
              ))}
            </div>
          </div>

          {/* Страница 2: контент раздела */}
          <div
            className={`sm-section-page${mobileView === "section" ? " sm-page-visible" : " sm-page-hidden-right"}`}
          >
            <div className="sm-topbar">
              <button
                className="sm-icon-btn sm-back-btn"
                onClick={() => setMobileView("list")}
              >
                <CaretLeft size={20} />
              </button>
              <h2 className="sm-title">
                {SECTIONS.find((s) => s.id === activeSection)?.label}
              </h2>
            </div>

            <div className="sm-section-content">{renderContent()}</div>
          </div>
        </div>
      </>
    );
  }

  /* ── Десктопный рендер — без изменений ── */
  return (
    <>
      <div
        className={`settings-overlay ${isAnimated ? "visible" : ""}`}
        onClick={onClose}
      />
      <div className={`settings-modal ${isAnimated ? "open" : ""}`}>
        <button className="settings-close-button" onClick={onClose}>
          <X size={24} />
        </button>
        <div className="settings-content">
          <SettingsSidebar
            activeSection={activeSection}
            onSectionChange={setActiveSection}
          />
          <div className="settings-main">{renderContent()}</div>
        </div>
      </div>
    </>
  );
}
