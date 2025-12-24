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
  avatar_path?: string | null;
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
    messageType?: "text" | "image" | "video" | "file" | "audio",
    mediaId?: string,
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
  syncContacts: (myUsername: string) => Promise<void>;
  editMessage: (
    messageId: string,
    newContent: string,
    myUsername: string,
  ) => Promise<void>;
  deleteMessage: (
    messageId: string,
    type: "for_me" | "for_everyone",
  ) => Promise<void>;
  handleMessageEdited: (
    data: {
      messageId: string;
      encrypted_content: string;
      edited_at: string;
    },
    myUsername: string,
  ) => Promise<void>;
  handleMessageDeleted: (
    data: {
      messageId: string;
      type: "for_me" | "for_everyone";
    },
    myUsername: string,
  ) => void;
  updateUserAvatar: (username: string, avatar_path: string | null) => void;
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
      setActiveChat: (username: string, myUsername: string) => {
        console.log(`📂 [setActiveChat] Opening chat with ${username}`);
        set({ activeChat: username });

        // Автоматически помечаем как прочитанное при открытии чата
        get().markAsRead(username);

        void myUsername; // Резерв для будущей логики
        // Отправляем на сервер
        get().markChatAsRead(username);

        // Отправляем WebSocket события message_read для всех непрочитанных сообщений
        const chatMessages = get().messages[username] || [];
        console.log(
          `📂 [setActiveChat] Found ${chatMessages.length} messages in chat`,
        );

        const unreadMessages = chatMessages.filter(
          (msg) => msg.sender_username === username && !msg.read_at,
        );

        console.log(
          `📂 [setActiveChat] Found ${unreadMessages.length} unread messages from ${username}`,
        );

        unreadMessages.forEach((msg) => {
          console.log(
            `📂 [setActiveChat] Message details: id=${msg.id}, sender=${msg.sender_username}, read_at=${msg.read_at}`,
          );
          socketService.emitMessageRead(msg.id, username);
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
                edited_at: msg.edited_at || null,
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
        messageType: "text" | "image" | "video" | "file" | "audio" = "text",
        mediaId?: string,
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
            message_type: messageType,
            media_id: mediaId,
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
            message_type: messageType,
            media_id: mediaId || null,
            created_at: response.data.created_at,
            delivered_at: null, // Еще не доставлено
            read_at: null,
          };

          console.log(
            `📤 [sendMessage] Adding MY message to store: id=${newMessage.id.slice(0, 8)}..., to=${recipientUsername}, type=${messageType}, media_id=${mediaId || "none"}`,
          );

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
            console.log(
              `✅ [addMessage] Auto-marking as read: id=${message.id.slice(0, 8)}..., sender=${message.sender_username}, myUsername=${myUsername}, isInActiveChat=${isInActiveChat}`,
            );

            // ВАЖНАЯ ПРОВЕРКА: не отправляем read receipt для своих сообщений
            if (
              message.sender_username.toLowerCase() === myUsername.toLowerCase()
            ) {
              console.error(
                `❌ [addMessage] BLOCKED: Attempted to send read receipt for OWN message!`,
              );
              // Не прерываем выполнение, продолжаем добавление сообщения
            } else {
              // Отправим на сервер через timeout чтобы не блокировать UI
              setTimeout(() => {
                get().markChatAsRead(chatUsername);
                // Отправляем WebSocket событие message_read для обновления статуса у отправителя
                socketService.emitMessageRead(
                  message.id,
                  message.sender_username,
                );
                console.log(
                  `✅ Sent read receipt for message ${message.id.slice(0, 8)}... to ${message.sender_username}`,
                );
              }, 0);
            }
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
            avatar_path: existingContact?.avatar_path || null,
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

      /**
       * Редактирование сообщения
       */
      editMessage: async (
        messageId: string,
        newContent: string,
        myUsername: string,
      ) => {
        console.log(`✏️ Editing message ${messageId}`);

        // Найти сообщение в store
        const state = get();
        let message: Message | undefined;
        let chatUsername: string | undefined;

        for (const [chat, msgs] of Object.entries(state.messages)) {
          const found = msgs.find((m) => m.id === messageId);
          if (found) {
            message = found;
            chatUsername = chat;
            break;
          }
        }

        if (!message || !chatUsername) {
          throw new Error("Message not found");
        }

        // Шифруем новое содержимое
        const otherUsername =
          message.sender_username === myUsername
            ? message.recipient_username
            : message.sender_username;

        const encrypted = await cryptoService.encryptMessageForChat(
          newContent,
          otherUsername,
          myUsername,
        );

        // Отправляем на сервер
        const response = await apiService.editMessage(messageId, encrypted);

        if (!response.success) {
          throw new Error(response.error || "Failed to edit message");
        }

        // Обновляем локально (Socket.IO обновит у получателя)
        set((state) => {
          const updatedMessages = { ...state.messages };
          if (updatedMessages[chatUsername!]) {
            updatedMessages[chatUsername!] = updatedMessages[chatUsername!].map(
              (msg) =>
                msg.id === messageId
                  ? {
                      ...msg,
                      encrypted_content: newContent,
                      edited_at: new Date().toISOString(),
                    }
                  : msg,
            );
          }
          return { messages: updatedMessages };
        });

        console.log(`✅ Message ${messageId} edited successfully`);
      },

      /**
       * Удаление сообщения
       */
      deleteMessage: async (
        messageId: string,
        type: "for_me" | "for_everyone",
      ) => {
        console.log(`🗑️ Deleting message ${messageId} (${type})`);

        // Отправляем на сервер
        const response = await apiService.deleteMessage(messageId, type);

        if (!response.success) {
          throw new Error(response.error || "Failed to delete message");
        }

        // Локальное удаление (Socket.IO обновит у получателя)
        set((state) => {
          const updatedMessages = { ...state.messages };

          for (const chat of Object.keys(updatedMessages)) {
            updatedMessages[chat] = updatedMessages[chat].filter(
              (msg) => msg.id !== messageId,
            );
          }

          return { messages: updatedMessages };
        });

        console.log(`✅ Message ${messageId} deleted successfully`);
      },

      /**
       * Обработка события редактирования сообщения (Socket.IO)
       */
      handleMessageEdited: async (
        data: {
          messageId: string;
          encrypted_content: string;
          edited_at: string;
        },
        myUsername: string,
      ) => {
        console.log(`📝 Received message:edited event for ${data.messageId}`);

        const state = get();
        let found = false;

        for (const [chat, msgs] of Object.entries(state.messages)) {
          const msgIndex = msgs.findIndex((m) => m.id === data.messageId);

          if (msgIndex !== -1) {
            found = true;
            const message = msgs[msgIndex];

            // Определяем другого пользователя для расшифровки
            const otherUsername =
              message.sender_username === myUsername
                ? message.recipient_username
                : message.sender_username;

            // Расшифровываем новое содержимое
            try {
              const decrypted = await cryptoService.decryptMessageFromChat(
                data.encrypted_content,
                otherUsername,
                myUsername,
              );

              set((state) => {
                const updatedMessages = { ...state.messages };
                if (updatedMessages[chat]) {
                  updatedMessages[chat][msgIndex] = {
                    ...message,
                    encrypted_content: decrypted || "[Failed to decrypt]",
                    edited_at: data.edited_at,
                  };
                }
                return { messages: updatedMessages };
              });
            } catch (err) {
              console.error("Failed to decrypt edited message:", err);
            }

            break;
          }
        }

        if (!found) {
          console.warn(`Message ${data.messageId} not found in store`);
        }
      },

      /**
       * Обработка события удаления сообщения (Socket.IO)
       */
      handleMessageDeleted: (
        data: {
          messageId: string;
          type: "for_me" | "for_everyone";
        },
        myUsername: string,
      ) => {
        console.log(
          `🗑️ Received message:deleted event for ${data.messageId} (${data.type})`,
        );

        void myUsername; // Может понадобиться для проверки прав

        // Удаляем сообщение из store
        set((state) => {
          const updatedMessages = { ...state.messages };

          for (const chat of Object.keys(updatedMessages)) {
            updatedMessages[chat] = updatedMessages[chat].filter(
              (msg) => msg.id !== data.messageId,
            );
          }

          return { messages: updatedMessages };
        });
      },

      /**
       * Синхронизация контактов с сервера (Telegram-style)
       * Вызывается при загрузке приложения или подключении Socket.io
       */
      syncContacts: async (myUsername: string) => {
        console.log("🔄 Syncing contacts from server...");

        try {
          const response = await apiService.syncContacts();

          console.log("🔄 [syncContacts] Response:", response);

          if (!response.success || !response.data || !response.data.contacts) {
            console.error("Failed to sync contacts:", {
              success: response.success,
              data: response.data,
              error: response.error,
            });
            return;
          }

          const { contacts } = response.data;

          console.log(`✅ Synced ${contacts.length} contacts from server`);

          // Расшифровываем lastMessage для каждого контакта
          const decryptedContacts = await Promise.all(
            contacts.map(async (contact) => {
              try {
                const decrypted = await cryptoService.decryptMessageFromChat(
                  contact.lastMessage,
                  contact.username,
                  myUsername,
                );

                return {
                  username: contact.username,
                  lastMessage: decrypted || "[Failed to decrypt]",
                  lastMessageTime: contact.lastMessageTime,
                  unreadCount: contact.unreadCount,
                  isOnline: contact.isOnline,
                  avatar_path: contact.avatar_path || null,
                };
              } catch (err) {
                console.error(
                  `Failed to decrypt message for ${contact.username}:`,
                  err,
                );
                return {
                  username: contact.username,
                  lastMessage: "[Failed to decrypt]",
                  lastMessageTime: contact.lastMessageTime,
                  unreadCount: contact.unreadCount,
                  isOnline: contact.isOnline,
                  avatar_path: contact.avatar_path || null,
                };
              }
            }),
          );

          // Обновляем contacts в store
          set({ contacts: decryptedContacts });

          console.log(
            `✅ Updated ${decryptedContacts.length} contacts in store`,
          );
        } catch (err) {
          console.error("Sync contacts error:", err);
        }
      },

      /**
       * Обновление аватарки пользователя в контактах
       */
      updateUserAvatar: (username: string, avatar_path: string | null) => {
        console.log(
          `🔄 Updating avatar for ${username} to ${avatar_path || "null"}`,
        );

        set((state) => {
          const updatedContacts = state.contacts.map((contact) => {
            if (contact.username === username) {
              return { ...contact, avatar_path };
            }
            return contact;
          });

          return { contacts: updatedContacts };
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
