import { useState } from 'react'
import { LeftStrip } from './LeftStrip'
import { BurgerMenu } from './BurgerMenu'
import { Sidebar } from './Sidebar'
import { ChatWindow } from './ChatWindow'
import { EmailVerificationBanner } from '@/components/settings/EmailVerificationBanner'

export function ChatLayout() {
  const [isBurgerOpen, setIsBurgerOpen] = useState(false)
  const [activeChat, setActiveChat] = useState<string | null>(null)

  return (
    <div className="chat-layout">
      {/* Левая узкая полоска с бургером */}
      <LeftStrip onBurgerClick={() => setIsBurgerOpen(true)} />

      {/* Выдвижное меню */}
      <BurgerMenu 
        isOpen={isBurgerOpen} 
        onClose={() => setIsBurgerOpen(false)} 
      />

      {/* Сайдбар со списком чатов */}
      <Sidebar 
        activeChat={activeChat} 
        onChatSelect={setActiveChat} 
      />

      {/* Окно чата */}
      <ChatWindow activeChat={activeChat} />

      {/* Email Verification Banner */}
      <EmailVerificationBanner />
    </div>
  )
}