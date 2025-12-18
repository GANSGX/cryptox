import { useState, useEffect, useRef } from "react";
import "./EditMessageModal.css";

interface EditMessageModalProps {
  originalMessage: string;
  onSave: (newMessage: string) => Promise<void>;
  onClose: () => void;
}

export function EditMessageModal({
  originalMessage,
  onSave,
  onClose,
}: EditMessageModalProps) {
  const [message, setMessage] = useState(originalMessage);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    // Focus and select text on mount
    if (textareaRef.current) {
      textareaRef.current.focus();
      textareaRef.current.select();
    }

    // Handle Escape key
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        onClose();
      }
    };

    document.addEventListener("keydown", handleEscape);
    return () => document.removeEventListener("keydown", handleEscape);
  }, [onClose]);

  const handleSave = async () => {
    const trimmed = message.trim();

    if (!trimmed) {
      setError("Message cannot be empty");
      return;
    }

    if (trimmed === originalMessage.trim()) {
      onClose();
      return;
    }

    setIsSaving(true);
    setError(null);

    try {
      await onSave(trimmed);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save");
      setIsSaving(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSave();
    }
  };

  return (
    <div className="edit-message-modal-overlay" onClick={onClose}>
      <div className="edit-message-modal" onClick={(e) => e.stopPropagation()}>
        <div className="edit-message-header">
          <h3>Edit Message</h3>
          <button className="close-button" onClick={onClose}>
            ×
          </button>
        </div>

        <div className="edit-message-body">
          <textarea
            ref={textareaRef}
            className="edit-message-textarea"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Enter message..."
            rows={4}
            disabled={isSaving}
          />

          {error && <div className="edit-message-error">{error}</div>}

          <div className="edit-message-hint">
            Press <kbd>Enter</kbd> to save, <kbd>Shift+Enter</kbd> for new line
          </div>
        </div>

        <div className="edit-message-footer">
          <button
            className="btn btn-secondary"
            onClick={onClose}
            disabled={isSaving}
          >
            Cancel
          </button>
          <button
            className="btn btn-primary"
            onClick={handleSave}
            disabled={isSaving || !message.trim()}
          >
            {isSaving ? "Saving..." : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}
