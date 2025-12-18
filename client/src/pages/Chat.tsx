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
  const {
    addMessage,
    setUserTyping,
    removeUserTyping,
    handleMessageEdited,
    handleMessageDeleted,
  } = useChatStore();

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

    // Обработка редактирования сообщений
    const handleMessageEditedEvent = (data: unknown) => {
      const typedData = data as {
        message_id: string;
        encrypted_content: string;
        edited_at: string;
        sender_username: string;
        recipient_username: string;
      };
      console.log("✏️ Message edited:", typedData);
      handleMessageEdited(
        {
          messageId: typedData.message_id,
          encrypted_content: typedData.encrypted_content,
          edited_at: typedData.edited_at,
        },
        user.username,
      );
    };

    // Обработка удаления сообщений
    const handleMessageDeletedEvent = (data: unknown) => {
      const typedData = data as {
        message_id: string;
        type: "for_everyone" | "for_sender" | "for_recipient";
        sender_username: string;
        recipient_username: string;
      };
      console.log("🗑️ Message deleted:", typedData);
      const normalizedType =
        typedData.type === "for_sender" || typedData.type === "for_recipient"
          ? "for_me"
          : typedData.type;
      handleMessageDeleted(
        {
          messageId: typedData.message_id,
          type: normalizedType,
        },
        user.username,
      );
    };

    // Подписываемся на события
    socketService.onNewMessage(handleNewMessage);
    socketService.onUserTyping(handleUserTyping);
    socketService.onUserStoppedTyping(handleUserStoppedTyping);
    socketService.on("message:edited", handleMessageEditedEvent);
    socketService.on("message:deleted", handleMessageDeletedEvent);

    // Отписываемся при размонтировании
    return () => {
      console.log("🔌 Chat: Cleaning up WebSocket listeners");
      socketService.offNewMessage(handleNewMessage);
      socketService.offUserTyping(handleUserTyping);
      socketService.offUserStoppedTyping(handleUserStoppedTyping);
      socketService.off("message:edited", handleMessageEditedEvent);
      socketService.off("message:deleted", handleMessageDeletedEvent);
    };
  }, [
    user,
    addMessage,
    setUserTyping,
    removeUserTyping,
    handleMessageEdited,
    handleMessageDeleted,
  ]);

  return <ChatLayout />;
}
