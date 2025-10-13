import { Send } from 'lucide-react'
import { useState, KeyboardEvent } from 'react'

interface MessageInputProps {
  activeChat: string
}

export function MessageInput({ activeChat }: MessageInputProps) {
  const [message, setMessage] = useState('')

  const handleSend = () => {
    if (!message.trim()) return

    console.log('Sending message to:', activeChat, message)
    // TODO: Подключить отправку через chatStore
    
    setMessage('')
  }

  const handleKeyPress = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  return (
    <div className="message-input-container">
      <textarea
        className="message-input"
        placeholder="Type a message..."
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        onKeyPress={handleKeyPress}
        rows={1}
      />
      <button
        className="send-button"
        onClick={handleSend}
        disabled={!message.trim()}
      >
        <Send size={20} />
      </button>
    </div>
  )
}