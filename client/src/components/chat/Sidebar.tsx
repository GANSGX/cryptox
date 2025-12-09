import { Search } from "lucide-react";
import { useState, useEffect } from "react";
import { apiService } from "@/services/api.service";

interface SidebarProps {
  activeChat: string | null;
  onChatSelect: (username: string) => void;
}

interface SearchUser {
  username: string;
  avatar_path: string | null;
  bio: string | null;
}

export function Sidebar({ activeChat, onChatSelect }: SidebarProps) {
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
          setSearchResults(response.data.users);
        }
      } catch (err) {
        console.error("Search error:", err);
      } finally {
        setIsSearching(false);
      }
    }, 300); // Debounce 300ms

    return () => clearTimeout(searchTimeout);
  }, [searchQuery]);

  return (
    <div className="sidebar">
      {/* Header */}
      <div className="sidebar-header">
        <h2>Chats</h2>

        {/* Search */}
        <div style={{ position: "relative" }}>
          <Search
            size={18}
            style={{
              position: "absolute",
              left: "12px",
              top: "50%",
              transform: "translateY(-50%)",
              color: "var(--text-tertiary)",
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
        {isSearching ? (
          <div className="search-loading">Searching...</div>
        ) : searchQuery.trim().length >= 2 ? (
          searchResults.length > 0 ? (
            searchResults.map((user) => (
              <div
                key={user.username}
                className={`chat-item ${activeChat === user.username ? "active" : ""}`}
                onClick={() => {
                  onChatSelect(user.username);
                  setSearchQuery(""); // Очищаем поиск после выбора
                  setSearchResults([]);
                }}
              >
                <div className="chat-avatar">
                  {user.username.charAt(0).toUpperCase()}
                </div>
                <div className="chat-info">
                  <h4>{user.username}</h4>
                  {user.bio && <p>{user.bio}</p>}
                </div>
              </div>
            ))
          ) : (
            <div className="search-empty">No users found</div>
          )
        ) : (
          <div className="chat-list-empty">
            <p>Search for users to start chatting</p>
          </div>
        )}
      </div>
    </div>
  );
}
