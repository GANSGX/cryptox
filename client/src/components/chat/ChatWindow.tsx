import { useEffect, useRef, Fragment, useState } from "react";
import { MessageCircle } from "lucide-react";
import { MessageInput } from "./MessageInput";
import { MessageStatus } from "./MessageStatus";
import { DateSeparator } from "./DateSeparator";
import { FloatingDateHeader } from "./FloatingDateHeader";
import { useChatStore } from "@/store/chatStore";
import { useAuthStore } from "@/store/authStore";
import { formatMessageTime, isSameDay } from "@/utils/dateTime";

interface ChatWindowProps {
  activeChat: string | null;
}

export function ChatWindow({ activeChat }: ChatWindowProps) {
  const { user } = useAuthStore();
  const { messages, loadMessages, isLoading, typingUsers } = useChatStore();
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const messagesContainerRef = useRef<HTMLDivElement>(null);
  const scrollTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Состояние для floating date header
  const [floatingDate, setFloatingDate] = useState<string | null>(null);
  const [isScrolling, setIsScrolling] = useState(false);
  const [showFloating, setShowFloating] = useState(false);

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

    const handleScroll = () => {
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
    };

    container.addEventListener("scroll", handleScroll);

    return () => {
      container.removeEventListener("scroll", handleScroll);
      if (scrollTimeoutRef.current) {
        clearTimeout(scrollTimeoutRef.current);
      }
    };
  }, [activeChat]);

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
                <div className={`message ${isOwn ? "own" : ""}`}>
                  <div className="message-bubble">
                    {msg.encrypted_content}
                    <div className="message-time">
                      {formatMessageTime(msg.created_at)}
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
      <MessageInput activeChat={activeChat} />
    </div>
  );
}
