import { create } from "zustand";
import { persist } from "zustand/middleware";
import { apiService } from "@/services/api.service";
import { socketService } from "@/services/socket.service";
import { cryptoService } from "@/services/crypto.service";
import type { Message } from "@/types/message.types";

interface Contact {
  username: string;
  lastMessage: string;
  lastMessageTime: string;
  unreadCount: number;
  isOnline?: boolean;
}

interface ChatState {
  activeChat: string | null;
  messages: Record<string, Message[]>;
  contacts: Contact[];
  isLoading: boolean;
  typingUsers: Set<string>;

  // Actions
  setActiveChat: (username: string, myUsername: string) => void;
  loadMessages: (username: string, myUsername: string) => Promise<void>;
  sendMessage: (
    recipientUsername: string,
    message: string,
    myUsername: string,
  ) => Promise<void>;
  addMessage: (message: Message, myUsername: string) => void;
  updateContact: (contact: Contact) => void;
  markAsRead: (username: string) => void;
  startTyping: (chatId: string) => void;
  stopTyping: (chatId: string) => void;
  setUserTyping: (username: string) => void;
  removeUserTyping: (username: string) => void;
  markChatAsRead: (username: string) => Promise<void>;
  updateMessageStatus: (
    messageId: string,
    status: "delivered" | "read",
  ) => void;
}

export const useChatStore = create<ChatState>()(
  persist(
    (set, get) => ({
      activeChat: null,
      messages: {},
      contacts: [],
      isLoading: false,
      typingUsers: new Set(),

      /**
       * Установка активного чата (и пометка как прочитанное)
       */
      setActiveChat: (username: string, _myUsername: string) => {
        set({ activeChat: username });

        // Автоматически помечаем как прочитанное при открытии чата
        get().markAsRead(username);

        // Отправляем на сервер
        get().markChatAsRead(username);

        // Отправляем WebSocket события message_read для всех непрочитанных сообщений
        const chatMessages = get().messages[username] || [];
        const unreadMessages = chatMessages.filter(
          (msg) => msg.sender_username === username && !msg.read_at,
        );

        unreadMessages.forEach((msg) => {
          socketService.emitMessageRead(msg.id, username);
          console.log(
            `✅ Sent read receipt for message ${msg.id} to ${username}`,
          );
        });

        console.log(
          `📖 Opened chat with ${username}, marked as read (${unreadMessages.length} messages)`,
        );
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
                delivered_at: msg.delivered_at,
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
            delivered_at: null, // Еще не доставлено
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
      addMessage: (message: Message, myUsername: string) => {
        console.log(
          "🔄 chatStore.addMessage called with:",
          message,
          "myUsername:",
          myUsername,
        );

        set((state) => {
          // Определяем username собеседника (не меня!)
          const chatUsername =
            message.sender_username === myUsername
              ? message.recipient_username
              : message.sender_username;

          console.log("📊 Current activeChat:", state.activeChat);
          console.log("📊 Determined chatUsername:", chatUsername);

          const existingMessages = state.messages[chatUsername] || [];

          // ВАЖНО: Проверяем дубликаты перед добавлением
          const isDuplicate = existingMessages.some((m) => m.id === message.id);
          if (isDuplicate) {
            console.log("⚠️ Duplicate message detected, skipping:", message.id);
            return state; // Не изменяем state
          }

          const isInActiveChat = state.activeChat === chatUsername;

          // Если сообщение получено (я не отправитель) и я в этом чате → автоматически прочитано
          if (message.sender_username !== myUsername && isInActiveChat) {
            console.log("✅ Auto-marking as read (in active chat)");
            // Отправим на сервер через timeout чтобы не блокировать UI
            setTimeout(() => {
              get().markChatAsRead(chatUsername);
              // Отправляем WebSocket событие message_read для обновления статуса у отправителя
              socketService.emitMessageRead(
                message.id,
                message.sender_username,
              );
              console.log(
                `✅ Sent read receipt for message ${message.id} to ${message.sender_username}`,
              );
            }, 0);
          }

          // Обновляем контакт
          const lastMessagePreview =
            message.encrypted_content.length > 50
              ? message.encrypted_content.substring(0, 50) + "..."
              : message.encrypted_content;

          const existingContact = state.contacts.find(
            (c) => c.username === chatUsername,
          );
          const isMyMessage = message.sender_username === myUsername;

          // Логируем для отладки
          console.log("📊 Contact update:", {
            chatUsername,
            isMyMessage,
            isInActiveChat,
            currentUnread: existingContact?.unreadCount || 0,
            shouldIncrement: !isMyMessage && !isInActiveChat,
          });

          const updatedContact: Contact = {
            username: chatUsername,
            lastMessage: isMyMessage
              ? `You: ${lastMessagePreview}`
              : lastMessagePreview,
            lastMessageTime: message.created_at,
            // Увеличиваем unread только если:
            // 1. Сообщение НЕ от меня
            // 2. Я НЕ в активном чате с этим пользователем
            unreadCount:
              !isMyMessage && !isInActiveChat
                ? (existingContact?.unreadCount || 0) + 1
                : isMyMessage || isInActiveChat
                  ? 0 // Сбрасываем если я отправитель или в активном чате
                  : existingContact?.unreadCount || 0,
            isOnline: existingContact?.isOnline,
          };

          console.log("✅ Updated contact:", updatedContact);

          // Обновляем список контактов
          const otherContacts = state.contacts.filter(
            (c) => c.username !== chatUsername,
          );
          const newContacts = [updatedContact, ...otherContacts].sort(
            (a, b) =>
              new Date(b.lastMessageTime).getTime() -
              new Date(a.lastMessageTime).getTime(),
          );

          return {
            messages: {
              ...state.messages,
              [chatUsername]: [...existingMessages, message],
            },
            contacts: newContacts,
          };
        });
      },

      /**
       * Обновить контакт
       */
      updateContact: (contact: Contact) => {
        set((state) => {
          const otherContacts = state.contacts.filter(
            (c) => c.username !== contact.username,
          );
          return {
            contacts: [contact, ...otherContacts],
          };
        });
      },

      /**
       * Пометить как прочитанное (локально)
       */
      markAsRead: (username: string) => {
        set((state) => {
          const updatedContacts = state.contacts.map((contact) =>
            contact.username === username
              ? { ...contact, unreadCount: 0 }
              : contact,
          );
          return { contacts: updatedContacts };
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

      /**
       * Обновить статус сообщения (delivered/read)
       */
      updateMessageStatus: (
        messageId: string,
        status: "delivered" | "read",
      ) => {
        console.log(
          `🔄 updateMessageStatus called: messageId=${messageId}, status=${status}`,
        );

        set((state) => {
          let found = false;
          let actuallyUpdated = false;

          // Проходим по всем чатам и ищем сообщение
          const updatedMessages: Record<string, Message[]> = {};

          for (const [chatUsername, chatMessages] of Object.entries(
            state.messages,
          )) {
            updatedMessages[chatUsername] = chatMessages.map((msg) => {
              if (msg.id === messageId) {
                found = true;
                const now = new Date().toISOString();

                console.log(`📨 Found message in chat ${chatUsername}:`, msg);

                if (status === "delivered" && !msg.delivered_at) {
                  console.log(
                    `✅ Updating delivered_at for message ${messageId}`,
                  );
                  actuallyUpdated = true;
                  return { ...msg, delivered_at: now };
                }

                if (status === "read" && !msg.read_at) {
                  console.log(`✅ Updating read_at for message ${messageId}`);
                  actuallyUpdated = true;
                  return {
                    ...msg,
                    read_at: now,
                    delivered_at: msg.delivered_at || now,
                  };
                }

                console.log(
                  `⚠️ Message ${messageId} already has status ${status}`,
                );
              }
              return msg;
            });
          }

          if (!found) {
            console.warn(`⚠️ Message ${messageId} not found in any chat`);
            return state;
          }

          if (actuallyUpdated) {
            console.log(
              `✅ Successfully updated message ${messageId} to ${status}`,
            );
            return { messages: updatedMessages };
          }

          console.log(
            `ℹ️ No update needed for message ${messageId} (already ${status})`,
          );
          return state;
        });
      },
    }),
    {
      name: "chat-storage",
      partialize: (state) => ({
        contacts: state.contacts,
        messages: state.messages,
        // Don't persist: typingUsers (Set can't be serialized), isLoading, activeChat
      }),
    },
  ),
);
