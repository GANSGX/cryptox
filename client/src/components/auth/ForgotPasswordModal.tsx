import { X } from "lucide-react";
import { useState, useEffect } from "react";
import { createPortal } from "react-dom";
import { apiService } from "@/services/api.service";
import { isValidEmail } from "@/utils/crypto";
import "./ForgotPasswordModal.css";

interface ForgotPasswordModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function ForgotPasswordModal({
  isOpen,
  onClose,
}: ForgotPasswordModalProps) {
  const [isMounted, setIsMounted] = useState(false);
  const [isAnimated, setIsAnimated] = useState(false);

  const [email, setEmail] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

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
        setEmail("");
        setError("");
        setSuccess(false);
      }, 300);
      return () => clearTimeout(timer);
    }
  }, [isOpen, isMounted]);

  if (!isMounted) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    // Валидация email
    if (!email) {
      setError("Please enter your email address");
      return;
    }

    if (!isValidEmail(email)) {
      setError("Please enter a valid email address");
      return;
    }

    setIsLoading(true);

    try {
      const response = await apiService.forgotPassword(email);

      if (response.success) {
        setSuccess(true);
      } else {
        // Показываем ошибку только если это rate limit или cooldown
        if (
          response.error?.includes("Too many") ||
          response.error?.includes("wait")
        ) {
          setError(response.error);
        } else {
          // Для безопасности всё равно показываем success
          setSuccess(true);
        }
      }
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleClose = () => {
    setSuccess(false);
    onClose();
  };

  return createPortal(
    <>
      {/* Overlay */}
      <div
        className={`forgot-password-overlay ${isAnimated ? "visible" : ""}`}
        onClick={handleClose}
      />

      {/* Modal */}
      <div className={`forgot-password-modal ${isAnimated ? "open" : ""}`}>
        {/* Header */}
        <div className="forgot-password-header">
          <h2>Forgot Password</h2>
          <button className="forgot-password-close" onClick={handleClose}>
            <X size={24} />
          </button>
        </div>

        {/* Content */}
        <div className="forgot-password-content">
          {success ? (
            <div className="forgot-password-success">
              <div className="success-icon">📧</div>
              <h3>Check your email</h3>
              <p>
                If a user with this email exists, a password recovery email has
                been sent.
              </p>
              <p className="success-hint">
                Please check your inbox and follow the instructions to reset
                your password.
              </p>
              <button
                className="settings-btn settings-btn-primary"
                onClick={handleClose}
              >
                OK
              </button>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="forgot-password-form">
              <div className="forgot-password-info">
                <div className="forgot-password-icon">🔑</div>
                <h3>Reset your password</h3>
                <p>
                  Enter your email address and we'll send you a recovery link
                </p>
              </div>

              {error && <div className="forgot-password-error">{error}</div>}

              <div className="form-group">
                <label className="form-label">Email Address</label>
                <input
                  type="email"
                  className="form-input"
                  value={email}
                  onChange={(e) => setEmail(e.target.value.toLowerCase())}
                  placeholder="your@email.com"
                  disabled={isLoading}
                  autoFocus
                />
              </div>

              <div className="forgot-password-actions">
                <button
                  type="button"
                  className="settings-btn settings-btn-secondary"
                  onClick={handleClose}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="settings-btn settings-btn-primary"
                  disabled={isLoading || !email}
                >
                  {isLoading ? "Sending..." : "Send Recovery Email"}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </>,
    document.body,
  );
}
