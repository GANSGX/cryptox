import { useEffect } from "react";
import { ChatLayout } from "@/components/chat/ChatLayout";
import { socketService } from "@/services/socket.service";
import { useChatStore } from "@/store/chatStore";
import { useAuthStore } from "@/store/authStore";
import { cryptoService } from "@/services/crypto.service";
import type { Message } from "@/types/message.types";
import { debugLogger } from "@/utils/debugLogger";

export function Chat() {
  const { user } = useAuthStore();
  const { addMessage, setUserTyping, removeUserTyping } = useChatStore();

  useEffect(() => {
    // Initialize debug logger (Ctrl+Shift+D to toggle)
    debugLogger.init();
    debugLogger.log(
      "🚀 Chat component mounted - Press Ctrl+Shift+D to toggle debug panel",
    );
  }, []);

  useEffect(() => {
    if (!user) return;

    console.log("🎧 Chat: Setting up WebSocket listeners");

    // Обработка новых сообщений
    const handleNewMessage = async (rawData: unknown) => {
      const data = rawData as {
        message_id: string;
        sender_username: string;
        recipient_username: string;
        encrypted_content: string;
        message_type: "text" | "image" | "video" | "file" | "audio";
        created_at: string;
        delivered_at: string | null;
        read_at: string | null;
      };
      console.log("💬 New message received:", data);

      // Расшифровываем сообщение
      const otherUsername =
        data.sender_username === user.username
          ? data.recipient_username
          : data.sender_username;

      const decrypted = await cryptoService.decryptMessageFromChat(
        data.encrypted_content,
        otherUsername,
        user.username,
      );

      const message: Message = {
        id: data.message_id,
        sender_username: data.sender_username,
        recipient_username: data.recipient_username,
        encrypted_content: decrypted || "[Failed to decrypt]",
        message_type: data.message_type || "text",
        created_at: data.created_at,
        delivered_at: data.delivered_at || null,
        read_at: null,
      };

      console.log("📥 Adding message to store:", message);
      addMessage(message, user.username);
      console.log("✅ Message added to store");
    };

    // Обработка typing indicators
    const handleUserTyping = (data: { username: string; chatId: string }) => {
      console.log("⌨️ User typing:", data.username);
      setUserTyping(data.username);
    };

    const handleUserStoppedTyping = (data: {
      username: string;
      chatId: string;
    }) => {
      console.log("⏸️ User stopped typing:", data.username);
      removeUserTyping(data.username);
    };

    // Подписываемся на события
    socketService.onNewMessage(handleNewMessage);
    socketService.onUserTyping(handleUserTyping);
    socketService.onUserStoppedTyping(handleUserStoppedTyping);

    // Отписываемся при размонтировании
    return () => {
      console.log("🔌 Chat: Cleaning up WebSocket listeners");
      socketService.offNewMessage(handleNewMessage);
      socketService.offUserTyping(handleUserTyping);
      socketService.offUserStoppedTyping(handleUserStoppedTyping);
    };
  }, [user, addMessage, setUserTyping, removeUserTyping]);

  return <ChatLayout />;
}
