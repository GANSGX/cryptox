import {
  Send,
  Mic,
  Video,
  Paperclip,
  Image,
  FileText,
  Film,
  Music2,
  X,
  Check,
} from "lucide-react";
import { useState, KeyboardEvent, useRef, useEffect } from "react";
import { useChatStore } from "@/store/chatStore";
import { useAuthStore } from "@/store/authStore";
import { cryptoService } from "@/services/crypto.service";
import type { Message } from "@/types/message.types";

interface MessageInputProps {
  activeChat: string;
  editingMessage?: Message | null;
  onCancelEdit?: () => void;
  onSaveEdit?: (newContent: string) => Promise<void>;
}

export function MessageInput({
  activeChat,
  editingMessage,
  onCancelEdit,
  onSaveEdit,
}: MessageInputProps) {
  const { user } = useAuthStore();
  const { sendMessage, startTyping, stopTyping } = useChatStore();
  const [message, setMessage] = useState("");
  const [showHoverMenu, setShowHoverMenu] = useState(false);
  const [recordMode, setRecordMode] = useState<"voice" | "video">("voice");
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const typingTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const hoverTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const photoInputRef = useRef<HTMLInputElement>(null);
  const videoInputRef = useRef<HTMLInputElement>(null);
  const documentInputRef = useRef<HTMLInputElement>(null);
  const audioInputRef = useRef<HTMLInputElement>(null);
  const attachButtonRef = useRef<HTMLButtonElement>(null);

  // Загрузить текст редактируемого сообщения
  useEffect(() => {
    if (editingMessage) {
      setMessage(editingMessage.encrypted_content);
      textareaRef.current?.focus();
    }
  }, [editingMessage]);

  // Auto-resize textarea
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = "44px";
      const scrollHeight = textareaRef.current.scrollHeight;
      textareaRef.current.style.height = `${Math.min(scrollHeight, 120)}px`;
    }
  }, [message]);

  // Typing indicators
  useEffect(() => {
    if (message.trim() && user) {
      const chatId = cryptoService.createChatId(user.username, activeChat);
      startTyping(chatId);

      // Останавливаем индикатор через 3 секунды если не печатаем
      if (typingTimeoutRef.current) {
        clearTimeout(typingTimeoutRef.current);
      }
      typingTimeoutRef.current = setTimeout(() => {
        stopTyping(chatId);
      }, 3000);
    }

    return () => {
      if (typingTimeoutRef.current) {
        clearTimeout(typingTimeoutRef.current);
      }
    };
  }, [message, activeChat, user, startTyping, stopTyping]);

  // Cleanup hover timeout on unmount
  useEffect(() => {
    return () => {
      if (hoverTimeoutRef.current) {
        clearTimeout(hoverTimeoutRef.current);
      }
    };
  }, []);

  const handleSend = async () => {
    if (!message.trim() || !user) return;

    if (editingMessage && onSaveEdit) {
      // Режим редактирования
      await onSaveEdit(message);
      setMessage("");
    } else {
      // Обычная отправка
      const chatId = cryptoService.createChatId(user.username, activeChat);
      stopTyping(chatId);

      await sendMessage(activeChat, message, user.username);
      setMessage("");
    }
  };

  const handleCancel = () => {
    if (onCancelEdit) {
      onCancelEdit();
      setMessage("");
    }
  };

  const handleKeyPress = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    } else if (e.key === "Escape" && editingMessage) {
      e.preventDefault();
      handleCancel();
    }
  };

  const toggleRecordMode = () => {
    setRecordMode((prev) => (prev === "voice" ? "video" : "voice"));
  };

  // Handle file selection
  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    // TODO: Implement file upload logic
    console.log("Selected files:", files);
    alert(
      `Selected ${files.length} file(s). Upload functionality will be implemented soon.`,
    );

    // Reset input
    e.target.value = "";
  };

  // Open file input for any file type (on click)
  const handleAttachClick = () => {
    fileInputRef.current?.click();
  };

  // Show menu immediately
  const handleShowMenu = () => {
    if (hoverTimeoutRef.current) {
      clearTimeout(hoverTimeoutRef.current);
      hoverTimeoutRef.current = null;
    }
    setShowHoverMenu(true);
  };

  // Hide menu with delay (200ms) to allow moving mouse to menu
  const handleHideMenu = () => {
    if (hoverTimeoutRef.current) {
      clearTimeout(hoverTimeoutRef.current);
    }
    hoverTimeoutRef.current = setTimeout(() => {
      setShowHoverMenu(false);
    }, 200);
  };

  // Cancel hide when mouse enters menu
  const handleMenuEnter = () => {
    if (hoverTimeoutRef.current) {
      clearTimeout(hoverTimeoutRef.current);
      hoverTimeoutRef.current = null;
    }
  };

  return (
    <div className="message-input-wrapper">
      {/* Hidden File Inputs */}
      <input
        ref={fileInputRef}
        type="file"
        multiple
        style={{ display: "none" }}
        onChange={handleFileChange}
      />
      <input
        ref={photoInputRef}
        type="file"
        accept="image/*"
        multiple
        style={{ display: "none" }}
        onChange={handleFileChange}
      />
      <input
        ref={videoInputRef}
        type="file"
        accept="video/*"
        multiple
        style={{ display: "none" }}
        onChange={handleFileChange}
      />
      <input
        ref={documentInputRef}
        type="file"
        accept=".pdf,.doc,.docx,.txt,.zip,.rar"
        multiple
        style={{ display: "none" }}
        onChange={handleFileChange}
      />
      <input
        ref={audioInputRef}
        type="file"
        accept="audio/*"
        multiple
        style={{ display: "none" }}
        onChange={handleFileChange}
      />

      {/* Attach Menu - Shows on Hover */}
      {showHoverMenu && (
        <div
          className="attach-menu"
          onMouseEnter={handleMenuEnter}
          onMouseLeave={handleHideMenu}
        >
          <button
            className="attach-menu-item"
            onClick={() => {
              photoInputRef.current?.click();
              setShowHoverMenu(false);
            }}
          >
            <div className="attach-icon photo">
              <Image size={20} />
            </div>
            <span>Photo</span>
          </button>
          <button
            className="attach-menu-item"
            onClick={() => {
              videoInputRef.current?.click();
              setShowHoverMenu(false);
            }}
          >
            <div className="attach-icon video">
              <Film size={20} />
            </div>
            <span>Video</span>
          </button>
          <button
            className="attach-menu-item"
            onClick={() => {
              documentInputRef.current?.click();
              setShowHoverMenu(false);
            }}
          >
            <div className="attach-icon document">
              <FileText size={20} />
            </div>
            <span>Document</span>
          </button>
          <button
            className="attach-menu-item"
            onClick={() => {
              audioInputRef.current?.click();
              setShowHoverMenu(false);
            }}
          >
            <div className="attach-icon audio">
              <Music2 size={20} />
            </div>
            <span>Audio</span>
          </button>
        </div>
      )}

      {/* Main Input Container */}
      <div className="message-input-container-new">
        {/* Attach Button - только в обычном режиме */}
        {!editingMessage && (
          <button
            ref={attachButtonRef}
            className="action-button attach-button"
            onClick={handleAttachClick}
            onMouseEnter={handleShowMenu}
            onMouseLeave={handleHideMenu}
            title="Attach file"
          >
            <Paperclip size={20} />
          </button>
        )}

        {/* Input Field Wrapper */}
        <div className="input-field-wrapper">
          <textarea
            ref={textareaRef}
            className="message-input-new"
            placeholder={editingMessage ? "Edit message..." : "Message"}
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            onKeyPress={handleKeyPress}
            rows={1}
          />

          {/* Режим редактирования - крестик и галочка */}
          {editingMessage && (
            <>
              <button
                className="edit-button-inline cancel"
                onClick={handleCancel}
                title="Cancel (Esc)"
              >
                <X size={20} />
              </button>
              <button
                className="edit-button-inline save"
                onClick={handleSend}
                title="Save (Enter)"
                disabled={!message.trim()}
              >
                <Check size={20} />
              </button>
            </>
          )}

          {/* Обычный режим - Send кнопка */}
          {!editingMessage && message.trim() && (
            <button className="send-button-inline" onClick={handleSend}>
              <Send size={20} />
            </button>
          )}
        </div>

        {/* Voice/Video Button - показывается когда нет текста и не в режиме редактирования */}
        {!editingMessage && !message.trim() && (
          <button
            className="action-button record-button"
            onClick={toggleRecordMode}
            title={recordMode === "voice" ? "Voice Message" : "Video Message"}
          >
            {recordMode === "voice" ? <Mic size={20} /> : <Video size={20} />}
          </button>
        )}
      </div>
    </div>
  );
}
