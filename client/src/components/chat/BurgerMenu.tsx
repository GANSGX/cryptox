import { User, Settings, LogOut, X } from "lucide-react";
import { useAuthStore } from "@/store/authStore";
import { useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";
import { SettingsModal } from "@/components/settings/SettingsModal";
import { ProfileModal } from "@/components/settings/ProfileModal";

interface BurgerMenuProps {
  isOpen: boolean;
  onClose: () => void;
}

export function BurgerMenu({ isOpen, onClose }: BurgerMenuProps) {
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();

  const [isMounted, setIsMounted] = useState(false);
  const [isAnimated, setIsAnimated] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [showProfile, setShowProfile] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setIsMounted(true);
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          setIsAnimated(true);
        });
      });
    } else if (isMounted) {
      setIsAnimated(false);
      const timer = setTimeout(() => {
        setIsMounted(false);
      }, 300);
      return () => clearTimeout(timer);
    }
  }, [isOpen, isMounted]);

  if (!isMounted) return null;

  const handleLogout = () => {
    logout();
    navigate("/login", { replace: true });
  };

  return (
    <>
      {/* Overlay */}
      <div
        className={`burger-menu-overlay ${isAnimated ? "visible" : ""}`}
        onClick={onClose}
      />

      {/* Menu */}
      <div className={`burger-menu ${isAnimated ? "open" : ""}`}>
        {/* Header - Profile + Close Button */}
        <div className="burger-menu-header">
          <button className="close-button" onClick={onClose}>
            <X size={24} />
          </button>

          <div className="burger-menu-profile">
            <div className="profile-avatar">
              {user?.avatar_path ? (
                <img
                  src={`http://localhost:3001${user.avatar_path}`}
                  alt="Avatar"
                />
              ) : (
                user?.username.charAt(0).toUpperCase()
              )}
            </div>
            <div className="profile-info">
              <h3>{user?.username}</h3>
              <p>{user?.email}</p>
            </div>
          </div>
        </div>

        {/* Menu Items */}
        <div className="burger-menu-items">
          <div className="menu-item" onClick={() => setShowProfile(true)}>
            <User size={20} />
            <span>Profile</span>
          </div>
          <div className="menu-item" onClick={() => setShowSettings(true)}>
            <Settings size={20} />
            <span>Settings</span>
          </div>
        </div>

        {/* Logout Button */}
        <div style={{ padding: "0 0 8px 0" }}>
          <div className="menu-item danger" onClick={handleLogout}>
            <LogOut size={20} />
            <span>Logout</span>
          </div>
        </div>

        {/* Footer */}
        <div className="burger-menu-footer">CryptoX v0.1.0</div>
      </div>

      {/* Profile Modal */}
      <ProfileModal
        isOpen={showProfile}
        onClose={() => setShowProfile(false)}
      />

      {/* Settings Modal */}
      <SettingsModal
        isOpen={showSettings}
        onClose={() => setShowSettings(false)}
      />
    </>
  );
}
