export interface Message {
  id: string
  sender_username: string
  recipient_username: string
  encrypted_content: string
  message_type: 'text' | 'image' | 'video' | 'file' | 'audio'
  created_at: string
  read_at: string | null
}

export interface ChatPreview {
  username: string
  last_message: string
  unread_count: number
  timestamp: string
}