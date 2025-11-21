import { X } from "lucide-react";
import { useState, useEffect } from "react";
import { createPortal } from "react-dom";
import { apiService } from "@/services/api.service";
import { isValidPassword } from "@/utils/crypto";
import "./ChangePasswordModal.css";

interface ChangePasswordModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
}

export function ChangePasswordModal({
  isOpen,
  onClose,
  onSuccess,
}: ChangePasswordModalProps) {
  const [isMounted, setIsMounted] = useState(false);
  const [isAnimated, setIsAnimated] = useState(false);

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");

  // Анимация монтирования
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
        setCurrentPassword("");
        setNewPassword("");
        setConfirmPassword("");
        setError("");
      }, 300);
      return () => clearTimeout(timer);
    }
  }, [isOpen, isMounted]);

  if (!isMounted) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    // Валидация
    if (!currentPassword || !newPassword || !confirmPassword) {
      setError("Please fill in all fields");
      return;
    }

    if (!isValidPassword(newPassword)) {
      setError("New password must be at least 8 characters");
      return;
    }

    if (newPassword !== confirmPassword) {
      setError("New passwords do not match");
      return;
    }

    if (currentPassword === newPassword) {
      setError("New password must be different from current password");
      return;
    }

    setIsLoading(true);

    try {
      const response = await apiService.changePassword(
        currentPassword,
        newPassword,
      );

      if (response.success) {
        onSuccess();
        onClose();
      } else {
        setError(response.error || "Failed to change password");
      }
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  return createPortal(
    <>
      {/* Overlay */}
      <div
        className={`change-password-overlay ${isAnimated ? "visible" : ""}`}
        onClick={onClose}
      />

      {/* Modal */}
      <div className={`change-password-modal ${isAnimated ? "open" : ""}`}>
        {/* Header */}
        <div className="change-password-header">
          <h2>Change Password</h2>
          <button className="change-password-close" onClick={onClose}>
            <X size={24} />
          </button>
        </div>

        {/* Content */}
        <div className="change-password-content">
          <form onSubmit={handleSubmit} className="change-password-form">
            <div className="change-password-info">
              <div className="change-password-icon">🔑</div>
              <h3>Update your password</h3>
              <p>Enter your current password and choose a new one</p>
            </div>

            {error && <div className="change-password-error">{error}</div>}

            <div className="form-group">
              <label className="form-label">Current Password</label>
              <input
                type="password"
                className="form-input"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                placeholder="Enter current password"
                disabled={isLoading}
                autoFocus
              />
            </div>

            <div className="form-group">
              <label className="form-label">New Password</label>
              <input
                type="password"
                className="form-input"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Enter new password"
                disabled={isLoading}
              />
            </div>

            <div className="form-group">
              <label className="form-label">Confirm New Password</label>
              <input
                type="password"
                className="form-input"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm new password"
                disabled={isLoading}
              />
            </div>

            <div className="change-password-notice">
              <strong>Note:</strong> Changing your password will sign you out
              from all other devices.
            </div>

            <div className="change-password-actions">
              <button
                type="button"
                className="settings-btn settings-btn-secondary"
                onClick={onClose}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="settings-btn settings-btn-primary"
                disabled={
                  isLoading ||
                  !currentPassword ||
                  !newPassword ||
                  !confirmPassword
                }
              >
                {isLoading ? "Changing..." : "Change Password"}
              </button>
            </div>
          </form>
        </div>
      </div>
    </>,
    document.body,
  );
}
