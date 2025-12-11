import { useState, useEffect } from "react";
import { LeftStrip } from "./LeftStrip";
import { BurgerMenu } from "./BurgerMenu";
import { Sidebar } from "./Sidebar";
import { ChatWindow } from "./ChatWindow";
import { EmailVerificationBanner } from "@/components/settings/EmailVerificationBanner";
import { useChatStore } from "@/store/chatStore";
import { useAuthStore } from "@/store/authStore";
import { socketService } from "@/services/socket.service";

export function ChatLayout() {
  const { user } = useAuthStore();
  const { activeChat, setActiveChat, updateMessageStatus, addMessage } =
    useChatStore();
  const [isBurgerOpen, setIsBurgerOpen] = useState(false);

  const handleChatSelect = (username: string) => {
    if (user) {
      setActiveChat(username, user.username);
    }
  };

  // WebSocket listeners для delivery/read receipts
  useEffect(() => {
    if (!user) return;

    // Обработчик новых сообщений - отправляем delivery receipt
    const handleNewMessage = (data: {
      message_id: string;
      sender_username: string;
      recipient_username: string;
      encrypted_content: string;
      message_type: "text" | "image" | "video" | "file" | "audio";
      created_at: string;
      delivered_at: string | null;
      read_at: string | null;
    }) => {
      console.log("📨 New message received:", data);

      // Автоматически отправляем delivery receipt
      socketService.emitMessageDelivered(data.message_id, data.sender_username);
      console.log(
        `✅ Sent delivery receipt for message ${data.message_id} to ${data.sender_username}`,
      );

      // Добавляем сообщение в store (уже есть в другом месте, но для consistency)
      addMessage(
        {
          id: data.message_id,
          sender_username: data.sender_username,
          recipient_username: data.recipient_username,
          encrypted_content: data.encrypted_content,
          message_type: data.message_type,
          created_at: data.created_at,
          delivered_at: data.delivered_at,
          read_at: data.read_at,
        },
        user.username,
      );
    };

    // Обработчик обновлений статуса сообщений
    const handleStatusUpdate = (data: {
      messageId: string;
      status: "delivered" | "read";
    }) => {
      console.log("📊 Message status update:", data);
      updateMessageStatus(data.messageId, data.status);
    };

    socketService.onNewMessage(handleNewMessage);
    socketService.onMessageStatusUpdate(handleStatusUpdate);

    return () => {
      socketService.offNewMessage(handleNewMessage);
      socketService.offMessageStatusUpdate(handleStatusUpdate);
    };
  }, [user, updateMessageStatus, addMessage]);

  return (
    <div className="chat-layout">
      {/* Левая узкая полоска с бургером */}
      <LeftStrip onBurgerClick={() => setIsBurgerOpen(true)} />

      {/* Выдвижное меню */}
      <BurgerMenu
        isOpen={isBurgerOpen}
        onClose={() => setIsBurgerOpen(false)}
      />

      {/* Сайдбар со списком чатов */}
      <Sidebar activeChat={activeChat} onChatSelect={handleChatSelect} />

      {/* Окно чата */}
      <ChatWindow activeChat={activeChat} />

      {/* Email Verification Banner */}
      <EmailVerificationBanner />
    </div>
  );
}
