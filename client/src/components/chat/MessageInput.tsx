import {
  Send,
  Mic,
  Video,
  Paperclip,
  Image,
  FileText,
  User,
  MapPin,
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
  const [showAttachMenu, setShowAttachMenu] = useState(false);
  const [recordMode, setRecordMode] = useState<"voice" | "video">("voice");
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const typingTimeoutRef = useRef<NodeJS.Timeout | null>(null);

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

  return (
    <div className="message-input-wrapper">
      {/* Attach Menu */}
      {showAttachMenu && (
        <>
          <div
            className="attach-menu-overlay"
            onClick={() => setShowAttachMenu(false)}
          />
          <div className="attach-menu">
            <button
              className="attach-menu-item"
              onClick={() => {
                setShowAttachMenu(false);
              }}
            >
              <div className="attach-icon media">
                <Image size={20} />
              </div>
              <span>Photo or Video</span>
            </button>
            <button
              className="attach-menu-item"
              onClick={() => {
                setShowAttachMenu(false);
              }}
            >
              <div className="attach-icon file">
                <FileText size={20} />
              </div>
              <span>Document</span>
            </button>
            <button
              className="attach-menu-item"
              onClick={() => {
                setShowAttachMenu(false);
              }}
            >
              <div className="attach-icon contact">
                <User size={20} />
              </div>
              <span>Contact</span>
            </button>
            <button
              className="attach-menu-item"
              onClick={() => {
                setShowAttachMenu(false);
              }}
            >
              <div className="attach-icon location">
                <MapPin size={20} />
              </div>
              <span>Location</span>
            </button>
          </div>
        </>
      )}

      {/* Main Input Container */}
      <div className="message-input-container-new">
        {/* Attach Button - только в обычном режиме */}
        {!editingMessage && (
          <button
            className="action-button attach-button"
            onClick={() => setShowAttachMenu(!showAttachMenu)}
            title="Attach"
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
