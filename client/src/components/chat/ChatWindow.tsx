import { useEffect, useRef } from "react";
import { MessageCircle } from "lucide-react";
import { MessageInput } from "./MessageInput";
import { MessageStatus } from "./MessageStatus";
import { useChatStore } from "@/store/chatStore";
import { useAuthStore } from "@/store/authStore";

interface ChatWindowProps {
  activeChat: string | null;
}

export function ChatWindow({ activeChat }: ChatWindowProps) {
  const { user } = useAuthStore();
  const { messages, loadMessages, isLoading, typingUsers } = useChatStore();
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Загрузка сообщений при выборе чата
  useEffect(() => {
    if (activeChat && user) {
      loadMessages(activeChat, user.username);
    }
  }, [activeChat, user, loadMessages]);

  // Автоскролл при новых сообщениях
  const messagesLength = activeChat ? messages[activeChat]?.length : 0;
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messagesLength]);

  // Пустое состояние - нет выбранного чата
  if (!activeChat) {
    return (
      <div className="chat-window">
        <div className="empty-state">
          <MessageCircle size={64} />
          <h3>Select a chat</h3>
          <p>Choose a conversation from the sidebar to start messaging</p>
        </div>
      </div>
    );
  }

  const chatMessages = messages[activeChat] || [];
  const isTyping = typingUsers.has(activeChat);

  // Форматирование времени
  const formatTime = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  return (
    <div className="chat-window">
      {/* Header */}
      <div className="chat-header">
        <div className="chat-avatar">{activeChat.charAt(0).toUpperCase()}</div>
        <div>
          <h3>{activeChat}</h3>
          <p>{isTyping ? "typing..." : "online"}</p>
        </div>
      </div>

      {/* Messages */}
      <div className="messages-container">
        {isLoading ? (
          <div className="loading-messages">Loading messages...</div>
        ) : chatMessages.length === 0 ? (
          <div className="empty-chat">
            <p>No messages yet. Start the conversation!</p>
          </div>
        ) : (
          chatMessages.map((msg) => {
            const isOwn = msg.sender_username === user?.username;
            return (
              <div key={msg.id} className={`message ${isOwn ? "own" : ""}`}>
                <div className="message-bubble">
                  {msg.encrypted_content}
                  <div className="message-time">
                    {formatTime(msg.created_at)}
                    <MessageStatus
                      createdAt={msg.created_at}
                      deliveredAt={msg.delivered_at}
                      readAt={msg.read_at}
                      isSent={isOwn}
                    />
                  </div>
                </div>
              </div>
            );
          })
        )}

        {/* Индикатор печати */}
        {isTyping && (
          <div className="message">
            <div className="message-bubble typing-indicator">
              <span></span>
              <span></span>
              <span></span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <MessageInput activeChat={activeChat} />
    </div>
  );
}
