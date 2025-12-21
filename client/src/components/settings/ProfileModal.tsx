import {
  X,
  Calendar,
  Camera,
  ChevronLeft,
  ChevronRight,
  Trash2,
} from "lucide-react";
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

interface ProfilePhoto {
  id: string;
  photo_path: string;
  is_primary: boolean;
  position: number;
  created_at: string;
}

export function ProfileModal({ isOpen, onClose }: ProfileModalProps) {
  const { user, updateUserAvatar } = useAuthStore();
  const [isMounted, setIsMounted] = useState(false);
  const [isAnimated, setIsAnimated] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Profile data
  const [status, setStatus] = useState("");
  const [birthday, setBirthday] = useState("");

  // Privacy settings
  const [statusPrivacy, setStatusPrivacy] = useState<PrivacyOption>("everyone");
  const [onlinePrivacy, setOnlinePrivacy] = useState<PrivacyOption>("everyone");
  const [typingPrivacy, setTypingPrivacy] = useState<PrivacyOption>("everyone");

  // Photo gallery
  const [photos, setPhotos] = useState<ProfilePhoto[]>([]);
  const [currentPhotoIndex, setCurrentPhotoIndex] = useState(0);

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
      // Загружаем профиль
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

      // Загружаем галерею фотографий
      const photosResponse = await apiService.getProfilePhotos();
      if (photosResponse.success && photosResponse.data) {
        setPhotos(photosResponse.data.photos);
        // Устанавливаем текущую фотографию на первую (primary)
        setCurrentPhotoIndex(0);
      }
    } catch (error) {
      console.error("Failed to load profile data:", error);
    }
  };

  if (!isMounted) return null;

  const handleAvatarClick = () => {
    fileInputRef.current?.click();
  };

  const handleAvatarChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    // Загружаем фото в галерею
    try {
      const response = await apiService.uploadProfilePhoto(file);
      if (response.success && response.data) {
        console.log("Photo uploaded:", response.data.photo_path);

        // Перезагружаем данные пользователя чтобы обновить avatar_path в authStore
        const meResponse = await apiService.me();
        if (meResponse.success && meResponse.data) {
          updateUserAvatar(meResponse.data.avatar_path || null);
        }

        // Перезагружаем галерею
        await loadProfileData();
      } else {
        alert(response.error || "Failed to upload photo");
      }
    } catch (error) {
      console.error("Failed to upload photo:", error);
      alert("Failed to upload photo");
    }
  };

  const handlePreviousPhoto = () => {
    setCurrentPhotoIndex((prev) => (prev > 0 ? prev - 1 : photos.length - 1));
  };

  const handleNextPhoto = () => {
    setCurrentPhotoIndex((prev) => (prev < photos.length - 1 ? prev + 1 : 0));
  };

  const handleDeletePhoto = async () => {
    if (photos.length === 0) return;

    const currentPhoto = photos[currentPhotoIndex];
    if (
      !window.confirm(
        "Are you sure you want to delete this photo" +
          (currentPhoto.is_primary ? " (current avatar)" : "") +
          "?",
      )
    ) {
      return;
    }

    try {
      const response = await apiService.deleteProfilePhoto(currentPhoto.id);
      if (response.success) {
        // Перезагружаем данные пользователя чтобы обновить avatar_path в authStore
        const meResponse = await apiService.me();
        if (meResponse.success && meResponse.data) {
          updateUserAvatar(meResponse.data.avatar_path || null);
        }

        // Перезагружаем галерею
        await loadProfileData();
        // Корректируем индекс если нужно
        if (currentPhotoIndex >= photos.length - 1) {
          setCurrentPhotoIndex(Math.max(0, photos.length - 2));
        }
      } else {
        alert(response.error || "Failed to delete photo");
      }
    } catch (error) {
      console.error("Failed to delete photo:", error);
      alert("Failed to delete photo");
    }
  };

  const handleSetPrimary = async () => {
    if (photos.length === 0) return;

    const currentPhoto = photos[currentPhotoIndex];
    if (currentPhoto.is_primary) return; // Уже primary

    try {
      const response = await apiService.setPrimaryPhoto(currentPhoto.id);
      if (response.success) {
        // Перезагружаем данные пользователя чтобы обновить avatar_path в authStore
        const meResponse = await apiService.me();
        if (meResponse.success && meResponse.data) {
          updateUserAvatar(meResponse.data.avatar_path || null);
        }

        // Перезагружаем галерею
        await loadProfileData();
      } else {
        alert(response.error || "Failed to set primary photo");
      }
    } catch (error) {
      console.error("Failed to set primary photo:", error);
      alert("Failed to set primary photo");
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
          {/* Avatar Gallery Section */}
          <div className="profile-section">
            <div className="profile-avatar-container">
              <div className="profile-avatar-gallery">
                {/* Navigation arrows */}
                {photos.length > 1 && (
                  <>
                    <button
                      className="gallery-nav gallery-nav-left"
                      onClick={handlePreviousPhoto}
                    >
                      <ChevronLeft size={24} />
                    </button>
                    <button
                      className="gallery-nav gallery-nav-right"
                      onClick={handleNextPhoto}
                    >
                      <ChevronRight size={24} />
                    </button>
                  </>
                )}

                {/* Avatar display */}
                <div
                  className="profile-avatar-large"
                  onClick={handleAvatarClick}
                >
                  {photos.length > 0 && photos[currentPhotoIndex] ? (
                    <img
                      src={`http://localhost:3001${photos[currentPhotoIndex].photo_path}`}
                      alt="Avatar"
                    />
                  ) : user?.avatar_path ? (
                    <img
                      src={`http://localhost:3001${user.avatar_path}`}
                      alt="Avatar"
                    />
                  ) : (
                    <span>{user?.username.charAt(0).toUpperCase()}</span>
                  )}
                  <div className="profile-avatar-overlay">
                    <Camera size={20} />
                  </div>
                </div>

                {/* Delete button */}
                {photos.length > 0 && (
                  <button
                    className="gallery-delete-btn"
                    onClick={handleDeletePhoto}
                  >
                    <Trash2 size={18} />
                  </button>
                )}

                {/* Photo counter */}
                {photos.length > 0 && (
                  <div className="gallery-counter">
                    {currentPhotoIndex + 1} / {photos.length}
                    {photos[currentPhotoIndex]?.is_primary && (
                      <span className="primary-badge">Main</span>
                    )}
                  </div>
                )}

                {/* Set as primary button (if not primary) */}
                {photos.length > 0 &&
                  !photos[currentPhotoIndex]?.is_primary && (
                    <button
                      className="set-primary-btn"
                      onClick={handleSetPrimary}
                    >
                      Set as Main
                    </button>
                  )}

                <input
                  ref={fileInputRef}
                  type="file"
                  accept="image/*"
                  style={{ display: "none" }}
                  onChange={handleAvatarChange}
                />
              </div>
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
