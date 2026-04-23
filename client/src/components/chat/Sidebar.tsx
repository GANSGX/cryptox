import { MagnifyingGlass, BookmarkSimple, List } from "@phosphor-icons/react";
import { useState, useEffect } from "react";
import { apiService } from "@/services/api.service";
import { useAuthStore } from "@/store/authStore";
import { useChatStore } from "@/store/chatStore";
import { formatChatPreviewTime } from "@/utils/dateTime";

interface SidebarProps {
  activeChat: string | null;
  onChatSelect: (username: string) => void;
  hidden?: boolean;
  onBurgerClick?: () => void;
}

interface SearchUser {
  username: string;
  avatar_path: string | null;
  bio: string | null;
}

export function Sidebar({
  activeChat,
  onChatSelect,
  hidden,
  onBurgerClick,
}: SidebarProps) {
  const { user } = useAuthStore();
  const { contacts } = useChatStore();
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<SearchUser[]>([]);
  const [isSearching, setIsSearching] = useState(false);

  // Поиск пользователей при вводе
  useEffect(() => {
    if (searchQuery.trim().length < 2) {
      setSearchResults([]);
      return;
    }

    const searchTimeout = setTimeout(async () => {
      setIsSearching(true);
      try {
        const response = await apiService.searchUsers(searchQuery);
        if (response.success && response.data) {
          // Фильтруем текущего пользователя из результатов
          const filteredUsers = response.data.users.filter(
            (u) => u.username.toLowerCase() !== user?.username.toLowerCase(),
          );
          setSearchResults(filteredUsers);
        }
      } catch (err) {
        console.error("Search error:", err);
      } finally {
        setIsSearching(false);
      }
    }, 300); // Debounce 300ms

    return () => clearTimeout(searchTimeout);
  }, [searchQuery, user]);

  return (
    <div className={`sidebar${hidden ? " sidebar-hidden" : ""}`}>
      {/* Header */}
      <div className="sidebar-header">
        {/* Mobile burger button */}
        {onBurgerClick && (
          <button className="sidebar-mobile-burger" onClick={onBurgerClick}>
            <List size={22} />
          </button>
        )}
        {/* Search */}
        <div style={{ position: "relative" }}>
          <MagnifyingGlass
            size={18}
            style={{
              position: "absolute",
              left: "14px",
              top: "50%",
              transform: "translateY(-50%)",
              color: "rgba(255, 255, 255, 0.4)",
              zIndex: 10,
              pointerEvents: "none",
            }}
          />
          <input
            type="text"
            className="search-input"
            placeholder="Search users..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
      </div>

      {/* Chat List / Search Results */}
      <div className="chat-list">
        {/* Избранное (Saved Messages) - показываем когда не ищем */}
        {!searchQuery && user && (
          <div
            className={`chat-item saved-messages ${activeChat === user.username ? "active" : ""}`}
            onClick={() => onChatSelect(user.username)}
          >
            <div className="chat-avatar saved">
              <BookmarkSimple size={20} />
            </div>
            <div className="chat-info">
              <h4>Saved Messages</h4>
              <p>Messages to yourself</p>
            </div>
          </div>
        )}

        {isSearching ? (
          <div className="search-loading">Searching...</div>
        ) : searchQuery.trim().length >= 2 ? (
          // Показываем результаты поиска
          searchResults.length > 0 ? (
            searchResults.map((searchUser) => (
              <div
                key={searchUser.username}
                className={`chat-item ${activeChat === searchUser.username ? "active" : ""}`}
                onClick={() => {
                  onChatSelect(searchUser.username);
                  setSearchQuery(""); // Очищаем поиск после выбора
                  setSearchResults([]);
                }}
              >
                <div className="chat-avatar">
                  {searchUser.avatar_path ? (
                    <img
                      src={`http://localhost:3001${searchUser.avatar_path}`}
                      alt="Avatar"
                    />
                  ) : (
                    searchUser.username.charAt(0).toUpperCase()
                  )}
                </div>
                <div className="chat-info">
                  <h4>{searchUser.username}</h4>
                  {searchUser.bio && <p>{searchUser.bio}</p>}
                </div>
              </div>
            ))
          ) : (
            <div className="search-empty">No users found</div>
          )
        ) : // Показываем список контактов
        contacts.length > 0 ? (
          contacts
            // Фильтруем контакт с самим собой (для этого есть "Saved Messages")
            .filter((contact) => contact.username !== user?.username)
            .map((contact) => (
              <div
                key={contact.username}
                className={`chat-item ${activeChat === contact.username ? "active" : ""}`}
                onClick={() => onChatSelect(contact.username)}
              >
                <div className="chat-avatar">
                  {contact.avatar_path ? (
                    <img
                      src={`http://localhost:3001${contact.avatar_path}`}
                      alt="Avatar"
                    />
                  ) : (
                    contact.username.charAt(0).toUpperCase()
                  )}
                </div>
                <div className="chat-info">
                  <div className="chat-info-top">
                    <h4>{contact.username}</h4>
                    <span className="chat-time">
                      {formatChatPreviewTime(contact.lastMessageTime)}
                    </span>
                  </div>
                  <div className="chat-info-bottom">
                    <p className="chat-last-message">{contact.lastMessage}</p>
                    {contact.unreadCount > 0 && (
                      <span className="unread-badge">
                        {contact.unreadCount}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ))
        ) : (
          <div className="chat-list-empty">
            <p>Search for users to start chatting</p>
          </div>
        )}
      </div>
    </div>
  );
}
