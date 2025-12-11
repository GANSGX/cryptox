import { create } from "zustand";
import { apiService } from "@/services/api.service";
import { socketService } from "@/services/socket.service";
import { cryptoService } from "@/services/crypto.service";
import type { Message } from "@/types/message.types";

interface ChatState {
  activeChat: string | null;
  messages: Record<string, Message[]>;
  isLoading: boolean;
  typingUsers: Set<string>;

  // Actions
  setActiveChat: (username: string) => void;
  loadMessages: (username: string, myUsername: string) => Promise<void>;
  sendMessage: (
    recipientUsername: string,
    message: string,
    myUsername: string,
  ) => Promise<void>;
  addMessage: (message: Message, myUsername?: string) => void;
  startTyping: (chatId: string) => void;
  stopTyping: (chatId: string) => void;
  setUserTyping: (username: string) => void;
  removeUserTyping: (username: string) => void;
  markChatAsRead: (username: string) => Promise<void>;
}

export const useChatStore = create<ChatState>((set, get) => ({
  activeChat: null,
  messages: {},
  isLoading: false,
  typingUsers: new Set(),

  /**
   * Установка активного чата
   */
  setActiveChat: (username: string) => {
    set({ activeChat: username });
  },

  /**
   * Загрузка истории сообщений
   */
  loadMessages: async (username: string, myUsername: string) => {
    set({ isLoading: true });

    try {
      const response = await apiService.getMessages(username);

      if (!response.success || !response.data) {
        console.error("Failed to load messages:", response.error);
        set({ isLoading: false });
        return;
      }

      // Расшифровываем сообщения
      const decryptedMessages: Message[] = await Promise.all(
        response.data.messages.map(async (msg) => {
          const decrypted = await cryptoService.decryptMessageFromChat(
            msg.encrypted_content,
            username,
            myUsername,
          );

          return {
            id: msg.id,
            sender_username: msg.sender_username,
            recipient_username: msg.recipient_username,
            encrypted_content: decrypted || "[Failed to decrypt]",
            message_type: msg.message_type as
              | "text"
              | "image"
              | "video"
              | "file"
              | "audio",
            created_at: msg.created_at,
            read_at: msg.read_at,
          };
        }),
      );

      set((state) => ({
        messages: {
          ...state.messages,
          [username]: decryptedMessages.reverse(), // Сортируем по возрастанию
        },
        isLoading: false,
      }));
    } catch (err) {
      console.error("Load messages error:", err);
      set({ isLoading: false });
    }
  },

  /**
   * Отправка сообщения
   */
  sendMessage: async (
    recipientUsername: string,
    message: string,
    myUsername: string,
  ) => {
    try {
      // Шифруем сообщение
      const encryptedContent = await cryptoService.encryptMessageForChat(
        message,
        recipientUsername,
        myUsername,
      );

      const response = await apiService.sendMessage({
        recipient_username: recipientUsername,
        encrypted_content: encryptedContent,
        message_type: "text",
      });

      if (!response.success || !response.data) {
        console.error("Failed to send message:", response.error);
        return;
      }

      // Добавляем сообщение в локальный стор
      const newMessage: Message = {
        id: response.data.message_id,
        sender_username: myUsername,
        recipient_username: recipientUsername,
        encrypted_content: message, // Храним расшифрованное для отображения
        message_type: "text",
        created_at: response.data.created_at,
        read_at: null,
      };

      get().addMessage(newMessage, myUsername);
    } catch (err) {
      console.error("Send message error:", err);
    }
  },

  /**
   * Добавление сообщения в чат
   */
  addMessage: (message: Message, myUsername?: string) => {
    console.log(
      "🔄 chatStore.addMessage called with:",
      message,
      "myUsername:",
      myUsername,
    );
    set((state) => {
      // Определяем username собеседника (не меня!)
      // Если я отправитель - chatUsername = получатель
      // Если я получатель - chatUsername = отправитель
      const chatUsername = myUsername
        ? message.sender_username === myUsername
          ? message.recipient_username
          : message.sender_username
        : message.sender_username === state.activeChat
          ? message.sender_username
          : message.recipient_username;

      console.log("📊 Current activeChat:", state.activeChat);
      console.log("📊 My username:", myUsername);
      console.log("📊 Determined chatUsername:", chatUsername);

      const existingMessages = state.messages[chatUsername] || [];
      console.log("📊 Existing messages count:", existingMessages.length);

      const newMessages = {
        messages: {
          ...state.messages,
          [chatUsername]: [...existingMessages, message],
        },
      };

      console.log("✅ New messages state:", newMessages);
      return newMessages;
    });
  },

  /**
   * Начало печати
   */
  startTyping: (chatId: string) => {
    socketService.emitTypingStart(chatId);
  },

  /**
   * Остановка печати
   */
  stopTyping: (chatId: string) => {
    socketService.emitTypingStop(chatId);
  },

  /**
   * Установка статуса "печатает"
   */
  setUserTyping: (username: string) => {
    set((state) => {
      const newTypingUsers = new Set(state.typingUsers);
      newTypingUsers.add(username);
      return { typingUsers: newTypingUsers };
    });
  },

  /**
   * Удаление статуса "печатает"
   */
  removeUserTyping: (username: string) => {
    set((state) => {
      const newTypingUsers = new Set(state.typingUsers);
      newTypingUsers.delete(username);
      return { typingUsers: newTypingUsers };
    });
  },

  /**
   * Пометить чат как прочитанный
   */
  markChatAsRead: async (username: string) => {
    try {
      await apiService.markChatAsRead(username);
    } catch (err) {
      console.error("Mark as read error:", err);
    }
  },
}));
