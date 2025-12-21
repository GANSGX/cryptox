import { X, Calendar, Camera } from "lucide-react";
import { useState, useEffect, useRef } from "react";
import { useAuthStore } from "@/store/authStore";
import { CustomSelect } from "@/components/ui/CustomSelect";
import { apiService } from "@/services/api.service";
import "./ProfileModal.css";

interface ProfileModalProps {
  isOpen: boolean;
  onClose: () => void;
}

type PrivacyOption = "everyone" | "chats" | "friends" | "nobody";

export function ProfileModal({ isOpen, onClose }: ProfileModalProps) {
  const { user } = useAuthStore();
  const [isMounted, setIsMounted] = useState(false);
  const [isAnimated, setIsAnimated] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Profile data
  const [avatar, setAvatar] = useState<string | null>(null);
  const [status, setStatus] = useState("");
  const [birthday, setBirthday] = useState("");

  // Privacy settings
  const [statusPrivacy, setStatusPrivacy] = useState<PrivacyOption>("everyone");
  const [onlinePrivacy, setOnlinePrivacy] = useState<PrivacyOption>("everyone");
  const [typingPrivacy, setTypingPrivacy] = useState<PrivacyOption>("everyone");

  // Загрузка данных профиля при открытии модалки
  useEffect(() => {
    if (isOpen) {
      loadProfileData();
    }
  }, [isOpen]);

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
      }, 300);
      return () => clearTimeout(timer);
    }
  }, [isOpen, isMounted]);

  const loadProfileData = async () => {
    try {
      const response = await apiService.me();
      if (response.success && response.data) {
        setStatus(response.data.status || "");
        setBirthday(response.data.birthday || "");
        setStatusPrivacy(
          (response.data.status_privacy as PrivacyOption) || "everyone",
        );
        setOnlinePrivacy(
          (response.data.online_privacy as PrivacyOption) || "everyone",
        );
        setTypingPrivacy(
          (response.data.typing_privacy as PrivacyOption) || "everyone",
        );
      }
    } catch (error) {
      console.error("Failed to load profile data:", error);
    }
  };

  if (!isMounted) return null;

  const handleAvatarClick = () => {
    fileInputRef.current?.click();
  };

  const handleAvatarChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        setAvatar(event.target?.result as string);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleSave = async () => {
    setIsSaving(true);
    try {
      const response = await apiService.updateProfile({
        status: status || undefined,
        birthday: birthday || undefined,
        status_privacy: statusPrivacy,
        online_privacy: onlinePrivacy,
        typing_privacy: typingPrivacy,
      });

      if (response.success) {
        onClose();
      } else {
        console.error("Failed to update profile:", response.error);
        alert(response.error || "Failed to update profile");
      }
    } catch (error) {
      console.error("Error updating profile:", error);
      alert("Failed to update profile");
    } finally {
      setIsSaving(false);
    }
  };

  const privacyOptions: { value: PrivacyOption; label: string }[] = [
    { value: "everyone", label: "Everyone" },
    { value: "chats", label: "My Chats" },
    { value: "friends", label: "Friends Only" },
    { value: "nobody", label: "Nobody" },
  ];

  return (
    <>
      {/* Overlay */}
      <div
        className={`profile-overlay ${isAnimated ? "visible" : ""}`}
        onClick={onClose}
      />

      {/* Modal */}
      <div className={`profile-modal ${isAnimated ? "open" : ""}`}>
        {/* Header */}
        <div className="profile-modal-header">
          <h2>Edit Profile</h2>
          <button className="profile-close-button" onClick={onClose}>
            <X size={24} />
          </button>
        </div>

        {/* Content */}
        <div className="profile-modal-content">
          {/* Avatar Section */}
          <div className="profile-section">
            <div className="profile-avatar-container">
              <div className="profile-avatar-large" onClick={handleAvatarClick}>
                {avatar ? (
                  <img src={avatar} alt="Avatar" />
                ) : (
                  <span>{user?.username.charAt(0).toUpperCase()}</span>
                )}
                <div className="profile-avatar-overlay">
                  <Camera size={20} />
                </div>
              </div>
              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                style={{ display: "none" }}
                onChange={handleAvatarChange}
              />
            </div>
            <div className="profile-username">{user?.username}</div>
          </div>

          {/* Status */}
          <div className="profile-section">
            <label className="profile-label">Status</label>
            <input
              type="text"
              className="profile-input"
              placeholder="What's on your mind?"
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              maxLength={70}
            />
          </div>

          {/* Birthday */}
          <div className="profile-section">
            <label className="profile-label">
              <Calendar size={16} />
              Birthday
            </label>
            <input
              type="date"
              className="profile-input"
              value={birthday}
              onChange={(e) => setBirthday(e.target.value)}
            />
          </div>

          {/* Privacy Settings */}
          <div className="profile-section">
            <h3 className="profile-section-title">Privacy Settings</h3>

            {/* Who can see my status */}
            <div className="profile-privacy-setting">
              <label className="profile-privacy-label">
                Who can see my status
              </label>
              <CustomSelect
                value={statusPrivacy}
                onChange={(value) => setStatusPrivacy(value as PrivacyOption)}
                options={privacyOptions}
              />
            </div>

            {/* Who can see my online status */}
            <div className="profile-privacy-setting">
              <label className="profile-privacy-label">
                Who can see when I'm online
              </label>
              <CustomSelect
                value={onlinePrivacy}
                onChange={(value) => setOnlinePrivacy(value as PrivacyOption)}
                options={privacyOptions}
              />
            </div>

            {/* Who can see my typing status */}
            <div className="profile-privacy-setting">
              <label className="profile-privacy-label">
                Who can see typing indicators
              </label>
              <CustomSelect
                value={typingPrivacy}
                onChange={(value) => setTypingPrivacy(value as PrivacyOption)}
                options={privacyOptions}
              />
            </div>
          </div>
        </div>

        {/* Footer with Save button */}
        <div className="profile-modal-footer">
          <button
            className="profile-cancel-button"
            onClick={onClose}
            disabled={isSaving}
          >
            Cancel
          </button>
          <button
            className="profile-save-button"
            onClick={handleSave}
            disabled={isSaving}
          >
            {isSaving ? "Saving..." : "Save Changes"}
          </button>
        </div>
      </div>
    </>
  );
}
