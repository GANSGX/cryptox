import { MessageCircle } from 'lucide-react'
import { MessageInput } from './MessageInput'

interface ChatWindowProps {
  activeChat: string | null
}

export function ChatWindow({ activeChat }: ChatWindowProps) {
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
    )
  }

  // Заглушка - позже заменим на реальные сообщения из store
  const mockMessages = [
    { id: '1', text: 'Hey there!', own: false, time: '10:30' },
    { id: '2', text: 'Hi! How are you?', own: true, time: '10:31' },
    { id: '3', text: 'I\'m good, thanks! What about you?', own: false, time: '10:32' },
  ]

  return (
    <div className="chat-window">
      {/* Header */}
      <div className="chat-header">
        <div className="chat-avatar">{activeChat.charAt(0).toUpperCase()}</div>
        <div>
          <h3>{activeChat}</h3>
          <p>online</p>
        </div>
      </div>

      {/* Messages */}
      <div className="messages-container">
        {mockMessages.map((msg) => (
          <div key={msg.id} className={`message ${msg.own ? 'own' : ''}`}>
            <div className="message-bubble">
              {msg.text}
              <div className="message-time">{msg.time}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Input */}
      <MessageInput activeChat={activeChat} />
    </div>
  )
}