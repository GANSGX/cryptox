import { X, Phone, Video, Image, FileText } from "lucide-react";
import { useState, useEffect } from "react";
import { apiService } from "@/services/api.service";
import "./UserProfileModal.css";

interface UserProfileModalProps {
  isOpen: boolean;
  onClose: () => void;
  username: string | null;
}

interface UserProfile {
  username: string;
  email?: string;
  status?: string | null;
  birthday?: string | null;
  avatar_path?: string | null;
}

export function UserProfileModal({
  isOpen,
  onClose,
  username,
}: UserProfileModalProps) {
  const [isMounted, setIsMounted] = useState(false);
  const [isAnimated, setIsAnimated] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [profile, setProfile] = useState<UserProfile | null>(null);

  // Загрузка профиля пользователя
  useEffect(() => {
    if (isOpen && username) {
      loadUserProfile();
    }
  }, [isOpen, username]);

  // Анимация открытия/закрытия
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
        setProfile(null);
      }, 300);
      return () => clearTimeout(timer);
    }
  }, [isOpen, isMounted]);

  const loadUserProfile = async () => {
    if (!username) return;

    setIsLoading(true);
    try {
      // Пока используем search для получения базовой информации
      const response = await apiService.searchUsers(username);
      if (response.success && response.data) {
        const user = response.data.users.find((u) => u.username === username);
        if (user) {
          setProfile({
            username: user.username,
            avatar_path: user.avatar_path,
            status: user.bio, // Временно используем bio как status
          });
        }
      }
    } catch (error) {
      console.error("Failed to load user profile:", error);
    } finally {
      setIsLoading(false);
    }
  };

  if (!isMounted || !username) return null;

  const formatBirthday = (birthday: string | null | undefined) => {
    if (!birthday) return null;
    const date = new Date(birthday);
    return date.toLocaleDateString("en-US", {
      month: "long",
      day: "numeric",
      year: "numeric",
    });
  };

  return (
    <>
      {/* Overlay */}
      <div
        className={`user-profile-overlay ${isAnimated ? "visible" : ""}`}
        onClick={onClose}
      />

      {/* Modal */}
      <div className={`user-profile-modal ${isAnimated ? "open" : ""}`}>
        {/* Header */}
        <div className="user-profile-modal-header">
          <h2>Profile</h2>
          <button className="user-profile-close-button" onClick={onClose}>
            <X size={24} />
          </button>
        </div>

        {/* Content */}
        <div className="user-profile-modal-content">
          {isLoading ? (
            <div className="loading-profile">Loading profile...</div>
          ) : (
            <>
              {/* Avatar Section */}
              <div className="user-profile-section">
                <div className="user-profile-avatar-container">
                  <div className="user-profile-avatar-large">
                    <span>{username.charAt(0).toUpperCase()}</span>
                  </div>
                </div>
                <div className="user-profile-username">{username}</div>
              </div>

              {/* Action Buttons */}
              <div className="user-profile-actions">
                <button
                  className="user-profile-action-button"
                  title="Voice Call"
                >
                  <Phone size={20} />
                  <span>Call</span>
                </button>
                <button
                  className="user-profile-action-button"
                  title="Video Call"
                >
                  <Video size={20} />
                  <span>Video</span>
                </button>
                <button className="user-profile-action-button" title="Media">
                  <Image size={20} />
                  <span>Media</span>
                </button>
                <button className="user-profile-action-button" title="Files">
                  <FileText size={20} />
                  <span>Files</span>
                </button>
              </div>

              {/* Profile Info */}
              <div className="user-profile-info">
                <h3 className="user-profile-section-title">About</h3>

                {profile?.status ? (
                  <div className="user-profile-info-item">
                    <label>Status</label>
                    <p>{profile.status}</p>
                  </div>
                ) : null}

                {profile?.birthday ? (
                  <div className="user-profile-info-item">
                    <label>Birthday</label>
                    <p>{formatBirthday(profile.birthday)}</p>
                  </div>
                ) : null}

                {!profile?.status && !profile?.birthday && (
                  <div className="user-profile-empty">
                    <p>This profile is not filled out yet</p>
                    <span>👤</span>
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </>
  );
}
