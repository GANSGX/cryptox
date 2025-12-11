import {
  Send,
  Mic,
  Video,
  Paperclip,
  Image,
  FileText,
  User,
  MapPin,
} from "lucide-react";
import { useState, KeyboardEvent, useRef, useEffect } from "react";
import { useChatStore } from "@/store/chatStore";
import { useAuthStore } from "@/store/authStore";
import { cryptoService } from "@/services/crypto.service";

interface MessageInputProps {
  activeChat: string;
}

export function MessageInput({ activeChat }: MessageInputProps) {
  const { user } = useAuthStore();
  const { sendMessage, startTyping, stopTyping } = useChatStore();
  const [message, setMessage] = useState("");
  const [showAttachMenu, setShowAttachMenu] = useState(false);
  const [recordMode, setRecordMode] = useState<"voice" | "video">("voice");
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const typingTimeoutRef = useRef<NodeJS.Timeout | null>(null);

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

    const chatId = cryptoService.createChatId(user.username, activeChat);
    stopTyping(chatId);

    await sendMessage(activeChat, message, user.username);
    setMessage("");
  };

  const handleKeyPress = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
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
                console.log("Media selected");
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
                console.log("File selected");
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
                console.log("Contact selected");
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
                console.log("Location selected");
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
        {/* Attach Button */}
        <button
          className="action-button attach-button"
          onClick={() => setShowAttachMenu(!showAttachMenu)}
          title="Attach"
        >
          <Paperclip size={20} />
        </button>

        {/* Input Field Wrapper */}
        <div className="input-field-wrapper">
          <textarea
            ref={textareaRef}
            className="message-input-new"
            placeholder="Message"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            onKeyPress={handleKeyPress}
            rows={1}
          />

          {/* Send Button - показывается только при наличии текста */}
          {message.trim() && (
            <button className="send-button-inline" onClick={handleSend}>
              <Send size={20} />
            </button>
          )}
        </div>

        {/* Voice/Video Button - показывается когда нет текста */}
        {!message.trim() && (
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
