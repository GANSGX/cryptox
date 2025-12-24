import {
  X,
  Calendar,
  Camera,
  ChevronLeft,
  ChevronRight,
  Trash2,
  Check,
  ChevronDown,
  Star,
} from "lucide-react";
import { useState, useEffect, useRef, useCallback } from "react";
import { useAuthStore } from "@/store/authStore";
import { apiService } from "@/services/api.service";
import "./ProfileModal.css";

// Extract dominant color from image
const extractDominantColor = (imgElement: HTMLImageElement): string => {
  try {
    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    if (!ctx) return "rgba(82, 39, 255, 0.5)";

    // Use smaller size for better performance
    const size = 100;
    canvas.width = size;
    canvas.height = size;
    ctx.drawImage(imgElement, 0, 0, size, size);

    const imageData = ctx.getImageData(0, 0, size, size);
    const data = imageData.data;

    let r = 0,
      g = 0,
      b = 0;
    let count = 0;

    // Sample every 10th pixel for performance
    for (let i = 0; i < data.length; i += 40) {
      const alpha = data[i + 3];
      // Skip transparent pixels
      if (alpha > 128) {
        r += data[i];
        g += data[i + 1];
        b += data[i + 2];
        count++;
      }
    }

    if (count === 0) return "rgba(82, 39, 255, 0.5)";

    r = Math.floor(r / count);
    g = Math.floor(g / count);
    b = Math.floor(b / count);

    // Increase saturation for more vibrant glow
    const max = Math.max(r, g, b);
    const min = Math.min(r, g, b);
    const saturation = max === 0 ? 0 : (max - min) / max;

    if (saturation < 0.3) {
      // Boost colors if too desaturated
      const boost = 1.5;
      r = Math.min(255, Math.floor(r * boost));
      g = Math.min(255, Math.floor(g * boost));
      b = Math.min(255, Math.floor(b * boost));
    }

    return `rgba(${r}, ${g}, ${b}, 0.5)`;
  } catch (error) {
    console.warn("Failed to extract color from avatar:", error);
    return "rgba(82, 39, 255, 0.5)";
  }
};

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

const privacyOptions: { value: PrivacyOption; label: string }[] = [
  { value: "everyone", label: "Everyone" },
  { value: "chats", label: "My Chats" },
  { value: "friends", label: "Friends" },
  { value: "nobody", label: "Nobody" },
];

const months = [
  "January",
  "February",
  "March",
  "April",
  "May",
  "June",
  "July",
  "August",
  "September",
  "October",
  "November",
  "December",
];

export function ProfileModal({ isOpen, onClose }: ProfileModalProps) {
  const { user, updateUserAvatar } = useAuthStore();
  const [isMounted, setIsMounted] = useState(false);
  const [isAnimated, setIsAnimated] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Profile data
  const [status, setStatus] = useState("");
  const [birthday, setBirthday] = useState("");

  // Privacy settings
  const [statusPrivacy, setStatusPrivacy] = useState<PrivacyOption>("everyone");
  const [onlinePrivacy, setOnlinePrivacy] = useState<PrivacyOption>("everyone");
  const [typingPrivacy, setTypingPrivacy] = useState<PrivacyOption>("everyone");

  // Track if data is loaded (to prevent auto-save on first load)
  const [isDataLoaded, setIsDataLoaded] = useState(false);

  // Photo gallery
  const [photos, setPhotos] = useState<ProfilePhoto[]>([]);
  const [currentPhotoIndex, setCurrentPhotoIndex] = useState(0);
  const [avatarGlowColor, setAvatarGlowColor] = useState(
    "rgba(82, 39, 255, 0.5)",
  );
  const [isPhotoTransitioning, setIsPhotoTransitioning] = useState(false);

  // Focus states
  const [statusFocused, setStatusFocused] = useState(false);

  // Birthday picker
  const [showDatePicker, setShowDatePicker] = useState(false);
  const [datePickerMounted, setDatePickerMounted] = useState(false);
  const [datePickerReady, setDatePickerReady] = useState(false);
  const [selectedDay, setSelectedDay] = useState(1);
  const [selectedMonth, setSelectedMonth] = useState(0);
  const [selectedYear, setSelectedYear] = useState(new Date().getFullYear());

  // Temporary picker values (for cancel functionality)
  const [tempDay, setTempDay] = useState(1);
  const [tempMonth, setTempMonth] = useState(0);
  const [tempYear, setTempYear] = useState(new Date().getFullYear());

  // Dropdown states
  const [statusPrivacyOpen, setStatusPrivacyOpen] = useState(false);
  const [onlinePrivacyOpen, setOnlinePrivacyOpen] = useState(false);
  const [typingPrivacyOpen, setTypingPrivacyOpen] = useState(false);

  // Dropdown refs for positioning
  const statusDropdownRef = useRef<HTMLDivElement>(null);
  const onlineDropdownRef = useRef<HTMLDivElement>(null);
  const typingDropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (isOpen) {
      setIsDataLoaded(false);
      loadProfileData();
    } else {
      // Reset when closing
      setIsDataLoaded(false);
    }
  }, [isOpen]);

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      const target = e.target as Node;
      if (
        statusDropdownRef.current &&
        !statusDropdownRef.current.contains(target)
      ) {
        setStatusPrivacyOpen(false);
      }
      if (
        onlineDropdownRef.current &&
        !onlineDropdownRef.current.contains(target)
      ) {
        setOnlinePrivacyOpen(false);
      }
      if (
        typingDropdownRef.current &&
        !typingDropdownRef.current.contains(target)
      ) {
        setTypingPrivacyOpen(false);
      }
    };

    if (
      isOpen &&
      (statusPrivacyOpen || onlinePrivacyOpen || typingPrivacyOpen)
    ) {
      document.addEventListener("mousedown", handleClickOutside);
      return () => {
        document.removeEventListener("mousedown", handleClickOutside);
      };
    }
  }, [isOpen, statusPrivacyOpen, onlinePrivacyOpen, typingPrivacyOpen]);

  // Smart positioning for dropdowns relative to modal
  useEffect(() => {
    const positionDropdown = (
      wrapperRef: React.RefObject<HTMLDivElement | null>,
      isOpen: boolean,
    ) => {
      if (!isOpen || !wrapperRef.current) return;

      const wrapper = wrapperRef.current;
      const dropdown = wrapper.querySelector(
        ".custom-select-dropdown",
      ) as HTMLElement;
      const modal = document.querySelector(".profile-modal") as HTMLElement;

      if (!dropdown || !modal) return;

      // Get positions
      const wrapperRect = wrapper.getBoundingClientRect();
      const modalRect = modal.getBoundingClientRect();
      const dropdownRect = dropdown.getBoundingClientRect();

      const dropdownWidth = dropdownRect.width || 160;
      const dropdownHeight = dropdownRect.height || 200;
      const padding = 16;

      // Calculate position relative to wrapper (default: below and aligned right)
      let top = "calc(100% + 6px)";
      let bottom = "auto";
      let right = "0";
      let left = "auto";

      // Check if dropdown goes beyond modal's right edge
      const dropdownRight = wrapperRect.right;
      if (dropdownRight > modalRect.right - padding) {
        // Too close to right, align to right edge of wrapper
        right = "0";
      }

      // Check if dropdown goes beyond modal's left edge
      const dropdownLeft = wrapperRect.right - dropdownWidth;
      if (dropdownLeft < modalRect.left + padding) {
        // Too close to left, align to left edge of wrapper
        right = "auto";
        left = "0";
      }

      // Check if dropdown goes beyond modal's bottom edge
      const dropdownBottom = wrapperRect.bottom + 6 + dropdownHeight;
      if (dropdownBottom > modalRect.bottom - padding) {
        // Too close to bottom, show above
        top = "auto";
        bottom = "calc(100% + 6px)";
      }

      dropdown.style.top = top;
      dropdown.style.bottom = bottom;
      dropdown.style.right = right;
      dropdown.style.left = left;
    };

    positionDropdown(statusDropdownRef, statusPrivacyOpen);
    positionDropdown(onlineDropdownRef, onlinePrivacyOpen);
    positionDropdown(typingDropdownRef, typingPrivacyOpen);
  }, [statusPrivacyOpen, onlinePrivacyOpen, typingPrivacyOpen]);

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
        const birthdayValue = response.data.birthday || "";
        setBirthday(birthdayValue);

        // Parse birthday for picker, or use current date
        if (birthdayValue) {
          const parts = birthdayValue.split("-");
          if (parts.length === 3) {
            const [year, month, day] = parts;
            setSelectedYear(parseInt(year));
            setSelectedMonth(parseInt(month) - 1);
            setSelectedDay(parseInt(day));
          }
        } else {
          // If no birthday, initialize with current date
          const now = new Date();
          setSelectedYear(now.getFullYear());
          setSelectedMonth(now.getMonth());
          setSelectedDay(now.getDate());
        }

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

      const photosResponse = await apiService.getProfilePhotos();
      if (photosResponse.success && photosResponse.data) {
        setPhotos(photosResponse.data.photos);
        setCurrentPhotoIndex(0);
      }

      // Mark data as loaded to enable auto-save
      setIsDataLoaded(true);
    } catch (error) {
      console.error("Failed to load profile data:", error);
    }
  };

  const handleAvatarClick = () => {
    fileInputRef.current?.click();
  };

  const handleAvatarChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const response = await apiService.uploadProfilePhoto(file);
      if (response.success && response.data) {
        const meResponse = await apiService.me();
        if (meResponse.success && meResponse.data) {
          updateUserAvatar(meResponse.data.avatar_path || null);
        }
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
    if (isPhotoTransitioning) return;
    setIsPhotoTransitioning(true);
    setTimeout(() => {
      setCurrentPhotoIndex((prev) => (prev > 0 ? prev - 1 : photos.length - 1));
      setTimeout(() => setIsPhotoTransitioning(false), 10);
    }, 125);
  };

  const handleNextPhoto = () => {
    if (isPhotoTransitioning) return;
    setIsPhotoTransitioning(true);
    setTimeout(() => {
      setCurrentPhotoIndex((prev) => (prev < photos.length - 1 ? prev + 1 : 0));
      setTimeout(() => setIsPhotoTransitioning(false), 10);
    }, 125);
  };

  const handleDeletePhoto = async () => {
    if (photos.length === 0) return;

    const currentPhoto = photos[currentPhotoIndex];
    if (
      !window.confirm(
        "Delete this photo" +
          (currentPhoto.is_primary ? " (current avatar)" : "") +
          "?",
      )
    ) {
      return;
    }

    try {
      const response = await apiService.deleteProfilePhoto(currentPhoto.id);
      if (response.success) {
        const meResponse = await apiService.me();
        if (meResponse.success && meResponse.data) {
          updateUserAvatar(meResponse.data.avatar_path || null);
        }
        await loadProfileData();
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
    if (currentPhoto.is_primary) return;

    try {
      const response = await apiService.setPrimaryPhoto(currentPhoto.id);
      if (response.success) {
        const meResponse = await apiService.me();
        if (meResponse.success && meResponse.data) {
          updateUserAvatar(meResponse.data.avatar_path || null);
        }
        await loadProfileData();
      } else {
        alert(response.error || "Failed to set primary photo");
      }
    } catch (error) {
      console.error("Failed to set primary photo:", error);
      alert("Failed to set primary photo");
    }
  };

  // Auto-save profile (can save specific fields or all)
  const autoSaveProfile = useCallback(
    async (fields?: {
      status?: string;
      birthday?: string;
      status_privacy?: PrivacyOption;
      online_privacy?: PrivacyOption;
      typing_privacy?: PrivacyOption;
    }) => {
      if (!isDataLoaded) return; // Don't save on initial load

      try {
        const dataToSave = fields || {
          status: status || undefined,
          birthday: birthday || undefined,
          status_privacy: statusPrivacy,
          online_privacy: onlinePrivacy,
          typing_privacy: typingPrivacy,
        };

        const response = await apiService.updateProfile(dataToSave);

        if (!response.success) {
          console.error("Failed to update profile:", response.error);
        }
      } catch (error) {
        console.error("Error updating profile:", error);
      }
    },
    [
      isDataLoaded,
      status,
      birthday,
      statusPrivacy,
      onlinePrivacy,
      typingPrivacy,
    ],
  );

  // Auto-save status with debounce (800ms like Telegram)
  useEffect(() => {
    if (!isDataLoaded) return;

    const timeoutId = setTimeout(() => {
      autoSaveProfile({ status });
    }, 800);

    return () => clearTimeout(timeoutId);
  }, [status, isDataLoaded, autoSaveProfile]);

  // Auto-save privacy settings immediately
  useEffect(() => {
    if (!isDataLoaded) return;
    autoSaveProfile({ status_privacy: statusPrivacy });
  }, [statusPrivacy, isDataLoaded, autoSaveProfile]);

  useEffect(() => {
    if (!isDataLoaded) return;
    autoSaveProfile({ online_privacy: onlinePrivacy });
  }, [onlinePrivacy, isDataLoaded, autoSaveProfile]);

  useEffect(() => {
    if (!isDataLoaded) return;
    autoSaveProfile({ typing_privacy: typingPrivacy });
  }, [typingPrivacy, isDataLoaded, autoSaveProfile]);

  // Format birthday for display
  const formatBirthday = () => {
    if (!birthday) return "Not set";
    return `${String(selectedDay).padStart(2, "0")} ${months[selectedMonth]} ${selectedYear}`;
  };

  // Generate years array from 1875 to current year
  const generateYears = () => {
    const currentYear = new Date().getFullYear();
    const years = [];
    for (let year = 1875; year <= currentYear; year++) {
      years.push(year);
    }
    return years;
  };

  // Initialize temp values when picker opens
  useEffect(() => {
    if (showDatePicker) {
      setDatePickerMounted(true);
      setDatePickerReady(false);
      setTempDay(selectedDay);
      setTempMonth(selectedMonth);
      setTempYear(selectedYear);

      // Wait for DOM to render, scroll instantly, then show
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          const wheels = document.querySelectorAll(".wheel");
          wheels.forEach((wheel, index) => {
            const items = Array.from(
              wheel.querySelectorAll<HTMLElement>(".wheel-item:not(.spacer)"),
            );

            let targetItem: HTMLElement | null = null;

            if (index === 0) {
              // Day wheel
              targetItem = items[selectedDay - 1];
            } else if (index === 1) {
              // Month wheel
              targetItem = items[selectedMonth];
            } else if (index === 2) {
              // Year wheel
              const years = generateYears();
              const yearIndex = years.findIndex((y) => y === selectedYear);
              if (yearIndex !== -1) {
                targetItem = items[yearIndex];
              }
            }

            if (targetItem) {
              const wheelElement = wheel as HTMLElement;
              const itemTop = targetItem.offsetTop;
              const itemHeight = targetItem.offsetHeight;
              const itemCenter = itemTop + itemHeight / 2;
              const wheelHalfHeight = wheelElement.clientHeight / 2;
              const targetScroll = itemCenter - wheelHalfHeight;

              wheelElement.scrollTo({
                top: targetScroll,
                behavior: "auto",
              });
            }
          });

          // Show modal after scroll is done
          requestAnimationFrame(() => {
            setDatePickerReady(true);
          });
        });
      });
    } else if (datePickerMounted) {
      // Animate out
      setDatePickerReady(false);
      const timer = setTimeout(() => {
        setDatePickerMounted(false);
      }, 250);
      return () => clearTimeout(timer);
    }
  }, [
    showDatePicker,
    selectedDay,
    selectedMonth,
    selectedYear,
    datePickerMounted,
  ]);

  // Snap to nearest item
  const snapToNearestItem = (wheelElement: HTMLElement) => {
    const items = Array.from(
      wheelElement.querySelectorAll<HTMLElement>(".wheel-item:not(.spacer)"),
    );
    if (items.length === 0) return;

    const wheelCenter = wheelElement.scrollTop + wheelElement.clientHeight / 2;
    let closestItem: HTMLElement | null = null;
    let minDistance = Infinity;

    items.forEach((item) => {
      const itemTop = item.offsetTop;
      const itemHeight = item.offsetHeight;
      const itemCenter = itemTop + itemHeight / 2;
      const distance = Math.abs(wheelCenter - itemCenter);

      if (distance < minDistance) {
        minDistance = distance;
        closestItem = item;
      }
    });

    if (closestItem) {
      const item = closestItem as HTMLElement;
      const itemTop = item.offsetTop;
      const itemHeight = item.offsetHeight;
      const itemCenter = itemTop + itemHeight / 2;
      const wheelHalfHeight = wheelElement.clientHeight / 2;
      const targetScroll = itemCenter - wheelHalfHeight;

      wheelElement.scrollTo({
        top: targetScroll,
        behavior: "smooth",
      });
    }
  };

  // Drag-scroll functionality
  const setupDragScroll = (wheelElement: HTMLElement) => {
    let isDragging = false;
    let startY = 0;
    let startScrollTop = 0;

    const handleMouseDown = (e: MouseEvent) => {
      isDragging = true;
      startY = e.clientY;
      startScrollTop = wheelElement.scrollTop;
      wheelElement.style.cursor = "grabbing";
      wheelElement.style.userSelect = "none";
      e.preventDefault();
    };

    const handleMouseMove = (e: MouseEvent) => {
      if (!isDragging) return;
      e.preventDefault();

      const totalDelta = startY - e.clientY;
      wheelElement.scrollTop = startScrollTop + totalDelta;
    };

    const handleMouseUp = () => {
      if (!isDragging) return;
      isDragging = false;
      wheelElement.style.cursor = "grab";
      wheelElement.style.userSelect = "auto";

      // Snap to nearest item after drag
      setTimeout(() => snapToNearestItem(wheelElement), 50);
    };

    wheelElement.addEventListener("mousedown", handleMouseDown);
    document.addEventListener("mousemove", handleMouseMove);
    document.addEventListener("mouseup", handleMouseUp);

    return () => {
      wheelElement.removeEventListener("mousedown", handleMouseDown);
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseup", handleMouseUp);
    };
  };

  // Update selected values based on scroll position
  const updateSelectedFromScroll = (
    wheelElement: HTMLElement,
    setter: (value: number) => void,
  ) => {
    const items = Array.from(
      wheelElement.querySelectorAll<HTMLElement>(".wheel-item:not(.spacer)"),
    );
    const wheelCenter = wheelElement.scrollTop + wheelElement.clientHeight / 2;

    let closestItem: HTMLElement | null = null;
    let closestValue = 0;
    let minDistance = Infinity;

    items.forEach((item, index) => {
      const itemTop = item.offsetTop;
      const itemCenter = itemTop + item.offsetHeight / 2;
      const distance = Math.abs(wheelCenter - itemCenter);

      if (distance < minDistance) {
        minDistance = distance;
        closestItem = item;
        closestValue = index;
      }
    });

    if (closestItem) {
      const wheelContainer = wheelElement.closest(".wheel-container");
      if (wheelContainer) {
        const label = wheelContainer.querySelector(".wheel-label")?.textContent;
        if (label === "Day") {
          setter(closestValue + 1);
        } else if (label === "Month") {
          setter(closestValue);
        } else if (label === "Year") {
          const years = generateYears();
          setter(years[closestValue]);
        }
      }
    }
  };

  // Setup drag-scroll for all wheels when picker opens
  useEffect(() => {
    if (showDatePicker) {
      setTimeout(() => {
        const wheels = document.querySelectorAll(".wheel");
        const cleanups: (() => void)[] = [];

        wheels.forEach((wheel, index) => {
          const wheelElement = wheel as HTMLElement;
          const cleanup = setupDragScroll(wheelElement);
          cleanups.push(cleanup);

          // Wheel event - scroll by one item at a time
          let wheelTimeout: NodeJS.Timeout;
          const handleWheel = (e: WheelEvent) => {
            e.preventDefault();

            const items = Array.from(
              wheelElement.querySelectorAll<HTMLElement>(
                ".wheel-item:not(.spacer)",
              ),
            );
            if (items.length === 0) return;

            const wheelCenter =
              wheelElement.scrollTop + wheelElement.clientHeight / 2;
            let currentIndex = 0;
            let minDistance = Infinity;

            items.forEach((item, idx) => {
              const itemTop = item.offsetTop;
              const itemHeight = item.offsetHeight;
              const itemCenter = itemTop + itemHeight / 2;
              const distance = Math.abs(wheelCenter - itemCenter);

              if (distance < minDistance) {
                minDistance = distance;
                currentIndex = idx;
              }
            });

            // Scroll up or down by one item
            const direction = e.deltaY > 0 ? 1 : -1;
            const targetIndex = Math.max(
              0,
              Math.min(items.length - 1, currentIndex + direction),
            );
            const targetItem = items[targetIndex];

            const itemTop = targetItem.offsetTop;
            const itemHeight = targetItem.offsetHeight;
            const itemCenter = itemTop + itemHeight / 2;
            const wheelHalfHeight = wheelElement.clientHeight / 2;
            const targetScroll = itemCenter - wheelHalfHeight;

            wheelElement.scrollTo({
              top: targetScroll,
              behavior: "smooth",
            });

            // Update temp value after scroll
            clearTimeout(wheelTimeout);
            wheelTimeout = setTimeout(() => {
              if (index === 0) {
                updateSelectedFromScroll(wheelElement, setTempDay);
              } else if (index === 1) {
                updateSelectedFromScroll(wheelElement, setTempMonth);
              } else if (index === 2) {
                updateSelectedFromScroll(wheelElement, setTempYear);
              }
            }, 200);
          };

          wheelElement.addEventListener("wheel", handleWheel, {
            passive: false,
          });
          cleanups.push(() => {
            wheelElement.removeEventListener("wheel", handleWheel);
            clearTimeout(wheelTimeout);
          });

          // Update temp value on scroll end (for drag)
          let scrollTimeout: NodeJS.Timeout;
          const handleScroll = () => {
            clearTimeout(scrollTimeout);
            scrollTimeout = setTimeout(() => {
              if (index === 0) {
                updateSelectedFromScroll(wheelElement, setTempDay);
              } else if (index === 1) {
                updateSelectedFromScroll(wheelElement, setTempMonth);
              } else if (index === 2) {
                updateSelectedFromScroll(wheelElement, setTempYear);
              }
            }, 150);
          };

          wheelElement.addEventListener("scroll", handleScroll);
          cleanups.push(() => {
            wheelElement.removeEventListener("scroll", handleScroll);
            clearTimeout(scrollTimeout);
          });
        });

        return () => {
          cleanups.forEach((cleanup) => cleanup());
        };
      }, 100);
    }
  }, [showDatePicker]);

  if (!isMounted) return null;

  return (
    <>
      <div
        className={`profile-overlay ${isAnimated ? "visible" : ""}`}
        onClick={onClose}
      />

      <div className={`profile-modal ${isAnimated ? "open" : ""}`}>
        <button className="profile-close-btn" onClick={onClose}>
          <X size={22} strokeWidth={2} />
        </button>

        <div className="profile-modal-content">
          {/* Avatar Gallery */}
          <div className="profile-header">
            <div className="profile-avatar-gallery">
              <div className="avatar-wrapper">
                <div
                  className="profile-avatar"
                  onClick={handleAvatarClick}
                  style={
                    {
                      "--avatar-glow": avatarGlowColor,
                    } as React.CSSProperties
                  }
                >
                  {photos.length > 0 && photos[currentPhotoIndex] ? (
                    <img
                      className={isPhotoTransitioning ? "transitioning" : ""}
                      src={`http://localhost:3001${photos[currentPhotoIndex].photo_path}`}
                      alt="Avatar"
                      crossOrigin="anonymous"
                      onLoad={(e) => {
                        const img = e.currentTarget;
                        const color = extractDominantColor(img);
                        setAvatarGlowColor(color);
                      }}
                    />
                  ) : user?.avatar_path ? (
                    <img
                      className={isPhotoTransitioning ? "transitioning" : ""}
                      src={`http://localhost:3001${user.avatar_path}`}
                      alt="Avatar"
                      crossOrigin="anonymous"
                      onLoad={(e) => {
                        const img = e.currentTarget;
                        const color = extractDominantColor(img);
                        setAvatarGlowColor(color);
                      }}
                    />
                  ) : (
                    <span>{user?.username.charAt(0).toUpperCase()}</span>
                  )}
                  <div className="avatar-overlay">
                    <Camera size={24} strokeWidth={2} />
                  </div>
                </div>

                {photos.length > 1 && (
                  <>
                    <button
                      className="gallery-nav gallery-nav-left"
                      onClick={handlePreviousPhoto}
                    >
                      <ChevronLeft size={18} strokeWidth={2.5} />
                    </button>
                    <button
                      className="gallery-nav gallery-nav-right"
                      onClick={handleNextPhoto}
                    >
                      <ChevronRight size={18} strokeWidth={2.5} />
                    </button>
                  </>
                )}
              </div>

              {photos.length > 0 && (
                <div className="gallery-controls">
                  <div className="gallery-counter">
                    {currentPhotoIndex + 1} / {photos.length}
                  </div>

                  <div className="gallery-buttons">
                    {photos[currentPhotoIndex]?.is_primary ? (
                      <div className="primary-indicator">
                        <Star size={14} strokeWidth={2} fill="currentColor" />
                        <span>Main Photo</span>
                      </div>
                    ) : (
                      <button
                        className="gallery-action-btn set-main"
                        onClick={handleSetPrimary}
                        title="Set as main photo"
                      >
                        <Star size={16} strokeWidth={2} />
                        <span>Set as Main</span>
                      </button>
                    )}
                    <button
                      className="gallery-action-btn delete"
                      onClick={handleDeletePhoto}
                      title="Delete photo"
                    >
                      <Trash2 size={16} strokeWidth={2} />
                      <span>Delete</span>
                    </button>
                  </div>
                </div>
              )}

              <input
                ref={fileInputRef}
                type="file"
                accept="image/*"
                style={{ display: "none" }}
                onChange={handleAvatarChange}
              />
            </div>

            <h2 className="profile-name">{user?.username}</h2>
            <p className="profile-email">{user?.email}</p>
          </div>

          {/* Status Input */}
          <div className="input-group">
            <label className="input-label">
              <span className="label-text">Status Message</span>
            </label>
            <div
              className={`custom-input ${statusFocused ? "focused" : ""} ${status ? "filled" : ""}`}
            >
              <input
                type="text"
                placeholder="What's on your mind?"
                value={status}
                onChange={(e) => setStatus(e.target.value)}
                onFocus={() => setStatusFocused(true)}
                onBlur={() => setStatusFocused(false)}
                maxLength={70}
              />
              <span className="input-length">{status.length}/70</span>
            </div>
          </div>

          {/* Birthday Picker Button */}
          <div className="input-group">
            <label className="input-label">
              <Calendar size={15} strokeWidth={2} />
              <span className="label-text">Date of Birth</span>
            </label>
            <button
              className="birthday-button"
              onClick={() => setShowDatePicker(true)}
            >
              <span className="birthday-value">{formatBirthday()}</span>
              <ChevronRight size={18} strokeWidth={2} />
            </button>
          </div>

          {/* Privacy Settings */}
          <div className="privacy-section">
            <h3 className="section-title">Privacy</h3>

            <div className="privacy-row">
              <span className="privacy-label">Status visibility</span>
              <div className="custom-select-wrapper" ref={statusDropdownRef}>
                <button
                  className="custom-select"
                  onClick={() => setStatusPrivacyOpen(!statusPrivacyOpen)}
                >
                  <span>
                    {
                      privacyOptions.find((opt) => opt.value === statusPrivacy)
                        ?.label
                    }
                  </span>
                  <ChevronDown
                    size={16}
                    strokeWidth={2}
                    className={statusPrivacyOpen ? "rotated" : ""}
                  />
                </button>
                {statusPrivacyOpen && (
                  <div className="custom-select-dropdown">
                    {privacyOptions.map((opt) => (
                      <button
                        key={opt.value}
                        className={`dropdown-option ${statusPrivacy === opt.value ? "selected" : ""}`}
                        onClick={() => {
                          setStatusPrivacy(opt.value);
                          setStatusPrivacyOpen(false);
                        }}
                      >
                        {opt.label}
                        {statusPrivacy === opt.value && (
                          <Check size={16} strokeWidth={2.5} />
                        )}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>

            <div className="privacy-row">
              <span className="privacy-label">Online status</span>
              <div className="custom-select-wrapper" ref={onlineDropdownRef}>
                <button
                  className="custom-select"
                  onClick={() => setOnlinePrivacyOpen(!onlinePrivacyOpen)}
                >
                  <span>
                    {
                      privacyOptions.find((opt) => opt.value === onlinePrivacy)
                        ?.label
                    }
                  </span>
                  <ChevronDown
                    size={16}
                    strokeWidth={2}
                    className={onlinePrivacyOpen ? "rotated" : ""}
                  />
                </button>
                {onlinePrivacyOpen && (
                  <div className="custom-select-dropdown">
                    {privacyOptions.map((opt) => (
                      <button
                        key={opt.value}
                        className={`dropdown-option ${onlinePrivacy === opt.value ? "selected" : ""}`}
                        onClick={() => {
                          setOnlinePrivacy(opt.value);
                          setOnlinePrivacyOpen(false);
                        }}
                      >
                        {opt.label}
                        {onlinePrivacy === opt.value && (
                          <Check size={16} strokeWidth={2.5} />
                        )}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>

            <div className="privacy-row">
              <span className="privacy-label">Typing indicators</span>
              <div className="custom-select-wrapper" ref={typingDropdownRef}>
                <button
                  className="custom-select"
                  onClick={() => setTypingPrivacyOpen(!typingPrivacyOpen)}
                >
                  <span>
                    {
                      privacyOptions.find((opt) => opt.value === typingPrivacy)
                        ?.label
                    }
                  </span>
                  <ChevronDown
                    size={16}
                    strokeWidth={2}
                    className={typingPrivacyOpen ? "rotated" : ""}
                  />
                </button>
                {typingPrivacyOpen && (
                  <div className="custom-select-dropdown">
                    {privacyOptions.map((opt) => (
                      <button
                        key={opt.value}
                        className={`dropdown-option ${typingPrivacy === opt.value ? "selected" : ""}`}
                        onClick={() => {
                          setTypingPrivacy(opt.value);
                          setTypingPrivacyOpen(false);
                        }}
                      >
                        {opt.label}
                        {typingPrivacy === opt.value && (
                          <Check size={16} strokeWidth={2.5} />
                        )}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Date Picker Wheel */}
      {datePickerMounted && (
        <>
          <div
            className={`date-picker-overlay ${datePickerReady ? "visible" : ""}`}
            onClick={() => setShowDatePicker(false)}
          />
          <div
            className={`date-picker-modal ${datePickerReady ? "ready" : ""}`}
          >
            <div className="date-picker-header">
              <button
                className="date-picker-btn cancel"
                onClick={() => setShowDatePicker(false)}
              >
                Cancel
              </button>
              <h3 className="date-picker-title">Date of Birth</h3>
              <button
                className="date-picker-btn done"
                onClick={async () => {
                  // Apply temp values to selected
                  setSelectedDay(tempDay);
                  setSelectedMonth(tempMonth);
                  setSelectedYear(tempYear);
                  const newBirthday = `${tempYear}-${String(tempMonth + 1).padStart(2, "0")}-${String(tempDay).padStart(2, "0")}`;
                  setBirthday(newBirthday);
                  setShowDatePicker(false);

                  // Auto-save birthday
                  if (isDataLoaded) {
                    await autoSaveProfile({ birthday: newBirthday });
                  }
                }}
              >
                Done
              </button>
            </div>

            <div className="date-picker-wheels">
              {/* Day Wheel */}
              <div className="wheel-container">
                <div className="wheel-label">Day</div>
                <div className="wheel">
                  <div className="wheel-item spacer"></div>
                  {Array.from({ length: 31 }, (_, i) => i + 1).map((day) => (
                    <div
                      key={day}
                      className={`wheel-item ${tempDay === day ? "selected" : ""}`}
                      onClick={() => setTempDay(day)}
                    >
                      {day}
                    </div>
                  ))}
                  <div className="wheel-item spacer"></div>
                </div>
              </div>

              {/* Month Wheel */}
              <div className="wheel-container">
                <div className="wheel-label">Month</div>
                <div className="wheel">
                  <div className="wheel-item spacer"></div>
                  {months.map((month, index) => (
                    <div
                      key={index}
                      className={`wheel-item ${tempMonth === index ? "selected" : ""}`}
                      onClick={() => setTempMonth(index)}
                    >
                      {month}
                    </div>
                  ))}
                  <div className="wheel-item spacer"></div>
                </div>
              </div>

              {/* Year Wheel */}
              <div className="wheel-container">
                <div className="wheel-label">Year</div>
                <div className="wheel">
                  <div className="wheel-item spacer"></div>
                  {generateYears().map((year) => (
                    <div
                      key={year}
                      className={`wheel-item ${tempYear === year ? "selected" : ""}`}
                      onClick={() => setTempYear(year)}
                    >
                      {year}
                    </div>
                  ))}
                  <div className="wheel-item spacer"></div>
                </div>
              </div>
            </div>

            <div className="wheel-selector-line" />
          </div>
        </>
      )}
    </>
  );
}
