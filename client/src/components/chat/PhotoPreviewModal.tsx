import { X, Image, FileText } from "lucide-react";
import { useState, useEffect } from "react";
import "./PhotoPreviewModal.css";

interface PhotoPreviewModalProps {
  file: File;
  isOpen: boolean;
  onClose: () => void;
  onSend: (file: File, mode: "photo" | "file") => Promise<void>;
}

export function PhotoPreviewModal({
  file,
  isOpen,
  onClose,
  onSend,
}: PhotoPreviewModalProps) {
  const [previewUrl, setPreviewUrl] = useState<string>("");
  const [isMounted, setIsMounted] = useState(false);
  const [isAnimated, setIsAnimated] = useState(false);
  const [isSending, setIsSending] = useState(false);

  useEffect(() => {
    if (isOpen) {
      // Create preview URL
      const url = URL.createObjectURL(file);
      setPreviewUrl(url);

      setIsMounted(true);
      setTimeout(() => setIsAnimated(true), 10);

      return () => {
        URL.revokeObjectURL(url);
      };
    } else {
      setIsAnimated(false);
      const timer = setTimeout(() => setIsMounted(false), 250);
      return () => clearTimeout(timer);
    }
  }, [isOpen, file]);

  const handleSend = async (mode: "photo" | "file") => {
    setIsSending(true);
    try {
      await onSend(file, mode);
      onClose();
    } catch (error) {
      console.error("Failed to send:", error);
      alert("Failed to send photo");
    } finally {
      setIsSending(false);
    }
  };

  if (!isMounted) return null;

  return (
    <>
      <div
        className={`photo-preview-overlay ${isAnimated ? "visible" : ""}`}
        onClick={onClose}
      />
      <div className={`photo-preview-modal ${isAnimated ? "open" : ""}`}>
        {/* Close Button */}
        <button className="photo-preview-close" onClick={onClose}>
          <X size={20} />
        </button>

        {/* Preview Image */}
        <div className="photo-preview-image-container">
          <img src={previewUrl} alt="Preview" className="photo-preview-image" />
        </div>

        {/* File Info */}
        <div className="photo-preview-info">
          <p className="photo-preview-filename">{file.name}</p>
          <p className="photo-preview-filesize">
            {(file.size / 1024 / 1024).toFixed(2)} MB
          </p>
        </div>

        {/* Action Buttons */}
        <div className="photo-preview-actions">
          <button
            className="photo-preview-btn send-as-photo"
            onClick={() => handleSend("photo")}
            disabled={isSending}
          >
            <Image size={20} />
            <div className="btn-text">
              <span className="btn-title">Send as Photo</span>
              <span className="btn-subtitle">Compressed, quick preview</span>
            </div>
          </button>

          <button
            className="photo-preview-btn send-as-file"
            onClick={() => handleSend("file")}
            disabled={isSending}
          >
            <FileText size={20} />
            <div className="btn-text">
              <span className="btn-title">Send as File</span>
              <span className="btn-subtitle">Original quality</span>
            </div>
          </button>
        </div>

        {/* Progress Indicator */}
        {isSending && (
          <div className="photo-preview-progress">
            <div className="spinner-large" />
            <p>Uploading...</p>
          </div>
        )}
      </div>
    </>
  );
}
