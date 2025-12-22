import {
  X,
  MessageCircle,
  Phone,
  Bell,
  MoreVertical,
  Image as ImageIcon,
  Video,
  File,
  Music,
  Link,
  Mic,
  FileImage,
  Users,
  ChevronRight,
} from "lucide-react";
import { useState, useEffect, useRef } from "react";
import { apiService } from "@/services/api.service";
import { ContextMenu, type ContextMenuItem } from "@/components/ui/ContextMenu";
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
  const [contextMenu, setContextMenu] = useState<{
    x: number;
    y: number;
  } | null>(null);
  const moreButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (isOpen && username) {
      loadUserProfile();
    }
  }, [isOpen, username]);

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
      const response = await apiService.searchUsers(username);
      if (response.success && response.data) {
        const user = response.data.users.find((u) => u.username === username);
        if (user) {
          setProfile({
            username: user.username,
            avatar_path: user.avatar_path,
            status: user.bio,
          });
        }
      }
    } catch (error) {
      console.error("Failed to load user profile:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleMoreClick = () => {
    if (!moreButtonRef.current) return;

    const rect = moreButtonRef.current.getBoundingClientRect();
    setContextMenu({
      x: rect.left,
      y: rect.bottom + 8,
    });
  };

  const moreMenuItems: ContextMenuItem[] = [
    {
      label: "Block User",
      icon: "ban",
      danger: true,
      onClick: () => {
        console.log("Block user:", username);
        setContextMenu(null);
      },
    },
    {
      label: "Delete Contact",
      icon: "delete",
      danger: true,
      onClick: () => {
        console.log("Delete contact:", username);
        setContextMenu(null);
      },
    },
  ];

  const mediaItems = [
    { icon: ImageIcon, label: "Photos", count: 0 },
    { icon: Video, label: "Videos", count: 0 },
    { icon: File, label: "Files", count: 0 },
    { icon: Music, label: "Music", count: 0 },
    { icon: Link, label: "Links", count: 0 },
    { icon: Mic, label: "Voice", count: 0 },
    { icon: FileImage, label: "GIFs", count: 0 },
    { icon: Users, label: "Groups in Common", count: 0 },
  ];

  if (!isMounted || !username) return null;

  return (
    <>
      <div
        className={`user-profile-overlay ${isAnimated ? "visible" : ""}`}
        onClick={onClose}
      />

      <div className={`user-profile-modal ${isAnimated ? "open" : ""}`}>
        <button className="user-profile-close-btn" onClick={onClose}>
          <X size={22} strokeWidth={2} />
        </button>

        <div className="user-profile-modal-content">
          {isLoading ? (
            <div className="loading-profile">Loading...</div>
          ) : (
            <>
              <div className="user-profile-header">
                <div className="user-profile-avatar">
                  {profile?.avatar_path ? (
                    <img
                      src={`http://localhost:3001${profile.avatar_path}`}
                      alt="Avatar"
                    />
                  ) : (
                    <span>{username.charAt(0).toUpperCase()}</span>
                  )}
                </div>
                <h2 className="user-profile-name">{username}</h2>
                <p className="user-profile-online">last seen recently</p>
              </div>

              <div className="user-profile-actions">
                <button className="action-btn">
                  <MessageCircle size={22} strokeWidth={1.5} />
                </button>
                <button className="action-btn">
                  <Bell size={22} strokeWidth={1.5} />
                </button>
                <button className="action-btn">
                  <Phone size={22} strokeWidth={1.5} />
                </button>
                <button
                  ref={moreButtonRef}
                  className="action-btn"
                  onClick={handleMoreClick}
                >
                  <MoreVertical size={22} strokeWidth={1.5} />
                </button>
              </div>

              <div className="status-section">
                {profile?.status ? (
                  <p className="status-text">{profile.status}</p>
                ) : (
                  <p className="status-empty">No status set</p>
                )}
              </div>

              <div className="media-list">
                {mediaItems.map((item, index) => (
                  <button key={index} className="media-row">
                    <div className="media-row-left">
                      <item.icon
                        size={22}
                        strokeWidth={1.5}
                        className="media-row-icon"
                      />
                      <span className="media-row-label">{item.label}</span>
                    </div>
                    <div className="media-row-right">
                      <span className="media-row-count">{item.count}</span>
                      <ChevronRight
                        size={18}
                        strokeWidth={1.5}
                        className="media-row-chevron"
                      />
                    </div>
                  </button>
                ))}
              </div>
            </>
          )}
        </div>
      </div>

      {contextMenu && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          items={moreMenuItems}
          onClose={() => setContextMenu(null)}
        />
      )}
    </>
  );
}
