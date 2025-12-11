import { useState } from "react";
import { LeftStrip } from "./LeftStrip";
import { BurgerMenu } from "./BurgerMenu";
import { Sidebar } from "./Sidebar";
import { ChatWindow } from "./ChatWindow";
import { EmailVerificationBanner } from "@/components/settings/EmailVerificationBanner";
import { useChatStore } from "@/store/chatStore";
import { useAuthStore } from "@/store/authStore";

export function ChatLayout() {
  const { user } = useAuthStore();
  const { activeChat, setActiveChat } = useChatStore();
  const [isBurgerOpen, setIsBurgerOpen] = useState(false);

  const handleChatSelect = (username: string) => {
    if (user) {
      setActiveChat(username, user.username);
    }
  };

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
      <Sidebar activeChat={activeChat} onChatSelect={handleChatSelect} />

      {/* Окно чата */}
      <ChatWindow activeChat={activeChat} />

      {/* Email Verification Banner */}
      <EmailVerificationBanner />
    </div>
  );
}
