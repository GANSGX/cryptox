import { useEffect, useRef, Fragment, useState } from "react";
import { MessageCircle } from "lucide-react";
import { MessageInput } from "./MessageInput";
import { MessageStatus } from "./MessageStatus";
import { DateSeparator } from "./DateSeparator";
import { FloatingDateHeader } from "./FloatingDateHeader";
import { ContextMenu, type ContextMenuItem } from "@/components/ui/ContextMenu";
import { useChatStore } from "@/store/chatStore";
import { useAuthStore } from "@/store/authStore";
import { formatMessageTime, isSameDay } from "@/utils/dateTime";
import type { Message } from "@/types/message.types";

interface ChatWindowProps {
  activeChat: string | null;
}

export function ChatWindow({ activeChat }: ChatWindowProps) {
  const { user } = useAuthStore();
  const {
    messages,
    loadMessages,
    isLoading,
    typingUsers,
    editMessage,
    deleteMessage,
  } = useChatStore();
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const messagesContainerRef = useRef<HTMLDivElement>(null);
  const scrollTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Состояние для floating date header
  const [floatingDate, setFloatingDate] = useState<string | null>(null);
  const [isScrolling, setIsScrolling] = useState(false);
  const [showFloating, setShowFloating] = useState(false);

  // Состояние для ContextMenu
  const [contextMenu, setContextMenu] = useState<{
    x: number;
    y: number;
    message: Message;
  } | null>(null);

  // Состояние для EditMessageModal
  const [editingMessage, setEditingMessage] = useState<Message | null>(null);

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

  // IntersectionObserver для отслеживания видимости статичных DateSeparator
  useEffect(() => {
    if (!messagesContainerRef.current || !activeChat) return;

    const container = messagesContainerRef.current;
    const dateSeparators = container.querySelectorAll(".date-separator");

    if (dateSeparators.length === 0) return;

    // IntersectionObserver для отслеживания статичных плашек
    const observer = new IntersectionObserver(
      (entries) => {
        // Найти первую видимую плашку сверху
        const visibleSeparators = entries
          .filter((entry) => entry.isIntersecting)
          .sort((a, b) => {
            const rectA = a.boundingClientRect;
            const rectB = b.boundingClientRect;
            return rectA.top - rectB.top;
          });

        if (visibleSeparators.length > 0) {
          // Если статичная плашка видна → прячем floating
          setShowFloating(false);
        } else if (isScrolling) {
          // Если скроллим и НИ ОДНА плашка не видна → показываем floating
          // Найти ПОСЛЕДНЮЮ плашку которая ушла вверх (ближайшую к viewport)
          const separatorsAboveViewport = Array.from(
            container.querySelectorAll(".date-separator"),
          ).filter((el) => {
            const rect = el.getBoundingClientRect();
            const containerRect = container.getBoundingClientRect();
            return rect.bottom < containerRect.top;
          });

          if (separatorsAboveViewport.length > 0) {
            // Последняя плашка из тех что ушли вверх
            const lastSeparatorAbove =
              separatorsAboveViewport[separatorsAboveViewport.length - 1];
            const date = lastSeparatorAbove.getAttribute("data-date");
            if (date) {
              setFloatingDate(date);
              setShowFloating(true);
            }
          }
        }
      },
      {
        root: container,
        rootMargin: "-80px 0px 0px 0px", // Offset для header
        threshold: 0,
      },
    );

    dateSeparators.forEach((separator) => observer.observe(separator));

    return () => observer.disconnect();
  }, [activeChat, messagesLength, isScrolling]);

  // Обработчик скролла для показа/скрытия floating header
  useEffect(() => {
    if (!messagesContainerRef.current) return;

    const container = messagesContainerRef.current;
    let throttleTimer: NodeJS.Timeout | null = null;

    const handleScroll = () => {
      // Throttle: выполнять максимум раз в 150ms
      if (throttleTimer) return;

      throttleTimer = setTimeout(() => {
        throttleTimer = null;

        // Начало скролла → показать floating
        setIsScrolling(true);

        // Найти последнюю плашку которая ушла вверх (для обновления даты)
        const separatorsAboveViewport = Array.from(
          container.querySelectorAll(".date-separator"),
        ).filter((el) => {
          const rect = el.getBoundingClientRect();
          const containerRect = container.getBoundingClientRect();
          return rect.bottom < containerRect.top;
        });

        if (separatorsAboveViewport.length > 0) {
          // Последняя плашка из тех что ушли вверх
          const lastSeparatorAbove =
            separatorsAboveViewport[separatorsAboveViewport.length - 1];
          const date = lastSeparatorAbove.getAttribute("data-date");
          if (date) {
            setFloatingDate(date);
          }
        }

        // Очистить предыдущий таймер
        if (scrollTimeoutRef.current) {
          clearTimeout(scrollTimeoutRef.current);
        }

        // Установить таймер на скрытие (0.5s после остановки)
        scrollTimeoutRef.current = setTimeout(() => {
          setIsScrolling(false);
          setShowFloating(false);
        }, 500);
      }, 150);
    };

    container.addEventListener("scroll", handleScroll, { passive: true });

    return () => {
      container.removeEventListener("scroll", handleScroll);
      if (scrollTimeoutRef.current) {
        clearTimeout(scrollTimeoutRef.current);
      }
      if (throttleTimer) {
        clearTimeout(throttleTimer);
      }
    };
  }, [activeChat]);

  // Проверка возможности редактирования (30 минут)
  const canEdit = (message: Message): boolean => {
    if (!user || message.sender_username !== user.username) return false;
    const thirtyMinutesAgo = Date.now() - 30 * 60 * 1000;
    return new Date(message.created_at).getTime() > thirtyMinutesAgo;
  };

  // Обработчик правого клика на сообщение
  const handleContextMenu = (e: React.MouseEvent, message: Message) => {
    e.preventDefault();
    e.stopPropagation();

    // Используем координаты клика - ContextMenu сам умно позиционируется
    setContextMenu({
      x: e.clientX,
      y: e.clientY,
      message,
    });
  };

  // Генерация опций контекстного меню
  const getContextMenuItems = (message: Message): ContextMenuItem[] => {
    if (!user) {
      return [];
    }

    const isOwn = message.sender_username === user.username;
    const canEditMsg = canEdit(message);
    const items: ContextMenuItem[] = [];

    // Edit (только свои сообщения + в течение 30 минут)
    if (isOwn && canEditMsg) {
      items.push({
        label: "Edit",
        icon: "edit",
        onClick: () => setEditingMessage(message),
      });
    }

    // Delete for everyone (только свои, БЕЗ ограничения времени как в Telegram)
    if (isOwn) {
      items.push({
        label: "Delete for everyone",
        icon: "delete",
        danger: true,
        onClick: () => handleDelete(message.id, "for_everyone"),
      });
    }

    // Delete for me (всегда доступно)
    items.push({
      label: "Delete for me",
      icon: "delete",
      danger: true,
      onClick: () => handleDelete(message.id, "for_me"),
    });

    return items;
  };

  // Обработчик удаления
  const handleDelete = async (
    messageId: string,
    type: "for_me" | "for_everyone",
  ) => {
    if (
      !window.confirm(
        `Are you sure you want to delete this message${type === "for_everyone" ? " for everyone" : ""}?`,
      )
    ) {
      return;
    }

    try {
      await deleteMessage(messageId, type);
    } catch (err) {
      console.error("Failed to delete message:", err);
      alert(err instanceof Error ? err.message : "Failed to delete message");
    }
  };

  // Обработчик сохранения отредактированного сообщения
  const handleSaveEdit = async (newContent: string) => {
    if (!editingMessage || !user) return;

    try {
      await editMessage(editingMessage.id, newContent, user.username);
      setEditingMessage(null); // Сбрасываем режим редактирования
    } catch (err) {
      console.error("Failed to edit message:", err);
      alert(err instanceof Error ? err.message : "Failed to edit message");
    }
  };

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

      {/* Floating Date Header (как в Telegram) */}
      <FloatingDateHeader date={floatingDate} visible={showFloating} />

      {/* Messages */}
      <div className="messages-container" ref={messagesContainerRef}>
        {isLoading ? (
          <div className="loading-messages">Loading messages...</div>
        ) : chatMessages.length === 0 ? (
          <div className="empty-chat">
            <p>No messages yet. Start the conversation!</p>
          </div>
        ) : (
          chatMessages.map((msg, index) => {
            const isOwn = msg.sender_username === user?.username;

            // Проверяем, нужно ли показать разделитель даты
            const showDateSeparator =
              index === 0 || // Первое сообщение - всегда показываем дату
              !isSameDay(
                new Date(msg.created_at),
                new Date(chatMessages[index - 1].created_at),
              );

            return (
              <Fragment key={msg.id}>
                {/* Разделитель даты (плашка) */}
                {showDateSeparator && <DateSeparator date={msg.created_at} />}

                {/* Само сообщение */}
                <div
                  className={`message ${isOwn ? "own" : ""} ${editingMessage?.id === msg.id ? "editing-mode" : ""}`}
                  onContextMenu={(e) => handleContextMenu(e, msg)}
                >
                  <div className="message-bubble">
                    {msg.encrypted_content}
                    <div className="message-time">
                      {formatMessageTime(msg.created_at)}
                      {msg.edited_at && (
                        <span className="edited-indicator" title="Edited">
                          (edited)
                        </span>
                      )}
                      <MessageStatus
                        createdAt={msg.created_at}
                        deliveredAt={msg.delivered_at}
                        readAt={msg.read_at}
                        isSent={isOwn}
                      />
                    </div>
                  </div>
                </div>
              </Fragment>
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
      <MessageInput
        activeChat={activeChat}
        editingMessage={editingMessage}
        onCancelEdit={() => setEditingMessage(null)}
        onSaveEdit={handleSaveEdit}
      />

      {/* Context Menu */}
      {contextMenu &&
        (() => {
          const items = getContextMenuItems(contextMenu.message);
          if (items.length === 0) return null;
          return (
            <ContextMenu
              x={contextMenu.x}
              y={contextMenu.y}
              items={items}
              onClose={() => setContextMenu(null)}
            />
          );
        })()}
    </div>
  );
}
