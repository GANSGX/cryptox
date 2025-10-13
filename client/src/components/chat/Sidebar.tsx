import { Search } from 'lucide-react'
import { useState } from 'react'

interface SidebarProps {
  activeChat: string | null
  onChatSelect: (username: string) => void
}

export function Sidebar({ activeChat, onChatSelect }: SidebarProps) {
  const [searchQuery, setSearchQuery] = useState('')

  // Заглушка - позже заменим на реальные чаты из store
  const mockChats = [
    { username: 'alice', lastMessage: 'Hey, how are you?', avatar: 'A' },
    { username: 'bob', lastMessage: 'Check this out!', avatar: 'B' },
    { username: 'charlie', lastMessage: 'See you tomorrow', avatar: 'C' },
  ]

  return (
    <div className="sidebar">
      {/* Header */}
      <div className="sidebar-header">
        <h2>Chats</h2>
        
        {/* Search */}
        <div style={{ position: 'relative' }}>
          <Search 
            size={18} 
            style={{ 
              position: 'absolute', 
              left: '12px', 
              top: '50%', 
              transform: 'translateY(-50%)',
              color: 'var(--text-tertiary)'
            }} 
          />
          <input
            type="text"
            className="search-input"
            placeholder="Search chats..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
      </div>

      {/* Chat List */}
      <div className="chat-list">
        {mockChats.map((chat) => (
          <div
            key={chat.username}
            className={`chat-item ${activeChat === chat.username ? 'active' : ''}`}
            onClick={() => onChatSelect(chat.username)}
          >
            <div className="chat-avatar">{chat.avatar}</div>
            <div className="chat-info">
              <h4>{chat.username}</h4>
              <p>{chat.lastMessage}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}