import {
  ChatCircle,
  Users,
  Gear,
  UserCircle,
  MagnifyingGlass,
} from "@phosphor-icons/react";
import "./MobileBottomNav.css";

export type MobileTab = "chats" | "contacts" | "settings" | "profile";

interface MobileBottomNavProps {
  activeTab: MobileTab;
  onTabChange: (tab: MobileTab) => void;
  onSearchFocus: () => void;
}

const tabs: { id: MobileTab; icon: typeof ChatCircle; label: string }[] = [
  { id: "chats", icon: ChatCircle, label: "Чаты" },
  { id: "contacts", icon: Users, label: "Контакты" },
  { id: "settings", icon: Gear, label: "Настройки" },
  { id: "profile", icon: UserCircle, label: "Профиль" },
];

export function MobileBottomNav({
  activeTab,
  onTabChange,
  onSearchFocus,
}: MobileBottomNavProps) {
  return (
    <div className="mobile-bottom-bar">
      <div className="mobile-nav-pill">
        {tabs.map(({ id, icon: Icon, label }) => {
          const isActive = activeTab === id;
          return (
            <button
              key={id}
              className={`mobile-nav-tab${isActive ? " active" : ""}`}
              onClick={() => onTabChange(id)}
              aria-label={label}
            >
              {/* Единая обёртка — пилюля захватывает и иконку и текст */}
              <span className="nav-tab-inner">
                <Icon size={22} weight={isActive ? "fill" : "regular"} />
                <span className="nav-tab-label">{label}</span>
              </span>
            </button>
          );
        })}
      </div>

      <button
        className="mobile-nav-search"
        onClick={onSearchFocus}
        aria-label="Поиск"
      >
        <MagnifyingGlass size={22} />
      </button>
    </div>
  );
}
