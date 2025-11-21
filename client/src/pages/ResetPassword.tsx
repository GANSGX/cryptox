import { useState, FormEvent, useEffect, useMemo } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { isValidPassword } from "@/utils/crypto";
import { apiService } from "@/services/api.service";
import LiquidEther from "@/components/ui/LiquidEther";
import "./ResetPassword.css";

export function ResetPassword() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token");

  const backgroundColors = useMemo(() => ["#5227FF", "#FF9FFC", "#B19EEF"], []);

  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);

  // Если нет токена - редирект на логин
  useEffect(() => {
    if (!token) {
      navigate("/login", { replace: true });
    }
  }, [token, navigate]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError("");

    // Валидация
    if (!newPassword || !confirmPassword) {
      setError("Please fill in all fields");
      return;
    }

    if (!isValidPassword(newPassword)) {
      setError("Password must be at least 8 characters");
      return;
    }

    if (newPassword !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }

    setIsLoading(true);

    try {
      const response = await apiService.resetPassword(token!, newPassword);

      if (response.success) {
        setSuccess(true);
        // Редирект на логин через 2 секунды
        setTimeout(() => {
          navigate("/login", { replace: true });
        }, 2000);
      } else {
        setError(response.error || "Failed to reset password");
      }
    } catch {
      setError("Network error. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  if (!token) {
    return null;
  }

  return (
    <div className="reset-password-container">
      {/* Анимированный фон */}
      <div
        style={{
          position: "fixed",
          top: 0,
          left: 0,
          width: "100%",
          height: "100%",
          zIndex: 0,
          pointerEvents: "none",
        }}
      >
        <LiquidEther
          key="background"
          colors={backgroundColors}
          mouseForce={25}
          cursorSize={80}
          autoDemo={true}
          autoSpeed={0.5}
          autoIntensity={1.7}
          resolution={0.5}
          autoResumeDelay={800}
          autoRampDuration={0.5}
        />
      </div>

      {/* Карточка */}
      <div
        className="reset-password-card"
        style={{ position: "relative", zIndex: 1 }}
      >
        {/* Logo */}
        <div className="reset-password-logo">
          <div className="logo-icon">
            <svg viewBox="0 0 24 24">
              <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z" />
            </svg>
          </div>
          <h1 className="logo-text">CryptoX</h1>
        </div>

        {success ? (
          <div className="reset-password-success">
            <div className="success-icon">✅</div>
            <h2>Password Reset Successful</h2>
            <p>Your password has been changed successfully.</p>
            <p className="redirect-message">Redirecting to login...</p>
          </div>
        ) : (
          <>
            <h2 className="reset-password-title">Reset Your Password</h2>

            {error && <div className="alert alert-error">{error}</div>}

            <form className="reset-password-form" onSubmit={handleSubmit}>
              <div className="form-group">
                <label className="form-label">New Password</label>
                <input
                  type="password"
                  className="form-input"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Enter new password"
                  disabled={isLoading}
                  autoFocus
                />
              </div>

              <div className="form-group">
                <label className="form-label">Confirm Password</label>
                <input
                  type="password"
                  className="form-input"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Confirm new password"
                  disabled={isLoading}
                />
              </div>

              <button
                type="submit"
                className="btn btn-primary"
                disabled={isLoading}
              >
                {isLoading ? (
                  <span className="loading"></span>
                ) : (
                  "Reset Password"
                )}
              </button>
            </form>

            <div className="reset-password-footer">
              <span
                className="reset-password-link"
                onClick={() => navigate("/login")}
              >
                Back to Login
              </span>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
