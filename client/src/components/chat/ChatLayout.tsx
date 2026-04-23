import { useState, useEffect } from "react";
import { LeftStrip } from "./LeftStrip";
import { BurgerMenu } from "./BurgerMenu";
import { Sidebar } from "./Sidebar";
import { ChatWindow } from "./ChatWindow";
import { MobileBottomNav, type MobileTab } from "./MobileBottomNav";
import { MobileSettingsPage } from "@/components/settings/MobileSettingsPage";
import { MobileContactsPage } from "./MobileContactsPage";
import { EmailVerificationBanner } from "@/components/settings/EmailVerificationBanner";
import { ProfileModal } from "@/components/settings/ProfileModal";
import { useChatStore } from "@/store/chatStore";
import { useAuthStore } from "@/store/authStore";
import { socketService } from "@/services/socket.service";

const MOBILE_BREAKPOINT = 768;

export function ChatLayout() {
  const { user } = useAuthStore();
  const { activeChat, setActiveChat, updateMessageStatus } = useChatStore();
  const [isBurgerOpen, setIsBurgerOpen] = useState(false);
  const [isMobile, setIsMobile] = useState(
    window.innerWidth <= MOBILE_BREAKPOINT,
  );
  const [showChatOnMobile, setShowChatOnMobile] = useState(false);
  const [activeTab, setActiveTab] = useState<MobileTab>("chats");

  useEffect(() => {
    const onResize = () => setIsMobile(window.innerWidth <= MOBILE_BREAKPOINT);
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  const handleChatSelect = (username: string) => {
    if (user) {
      setActiveChat(username, user.username);
      if (isMobile) {
        setShowChatOnMobile(true);
        setActiveTab("chats");
      }
    }
  };

  const handleTabChange = (tab: MobileTab) => {
    setActiveTab(tab);
    if (tab === "chats") setShowChatOnMobile(false);
  };

  const handleSearchFocus = () => {
    setActiveTab("chats");
    setShowChatOnMobile(false);
    setTimeout(() => {
      document.querySelector<HTMLInputElement>(".search-input")?.focus();
    }, 50);
  };

  useEffect(() => {
    if (!user) return;
    const handleNewMessage = (data: {
      message_id: string;
      sender_username: string;
      recipient_username: string;
      encrypted_content: string;
      message_type: "text" | "image" | "video" | "file" | "audio";
      created_at: string;
      delivered_at: string | null;
      read_at: string | null;
    }) => {
      socketService.emitMessageDelivered(data.message_id, data.sender_username);
    };
    const handleStatusUpdate = (data: {
      messageId: string;
      status: "delivered" | "read";
    }) => {
      updateMessageStatus(data.messageId, data.status);
    };
    socketService.onNewMessage(handleNewMessage);
    socketService.onMessageStatusUpdate(handleStatusUpdate);
    return () => {
      socketService.offNewMessage(handleNewMessage);
      socketService.offMessageStatusUpdate(handleStatusUpdate);
    };
  }, [user, updateMessageStatus]);

  const isChatsTab = activeTab === "chats";
  const sidebarHidden = isMobile && (showChatOnMobile || !isChatsTab);
  const chatHidden = isMobile && !showChatOnMobile;

  return (
    <div className={`chat-layout${isMobile ? " chat-layout-mobile" : ""}`}>
      {!isMobile && <LeftStrip onBurgerClick={() => setIsBurgerOpen(true)} />}

      <BurgerMenu
        isOpen={isBurgerOpen}
        onClose={() => setIsBurgerOpen(false)}
      />

      {/* Чаты */}
      <Sidebar
        activeChat={activeChat}
        onChatSelect={handleChatSelect}
        hidden={sidebarHidden}
      />

      <ChatWindow
        activeChat={activeChat}
        hidden={chatHidden}
        onBack={
          isMobile
            ? () => {
                setShowChatOnMobile(false);
              }
            : undefined
        }
      />

      {/* Контакты */}
      {isMobile && activeTab === "contacts" && (
        <div className="mobile-tab-page" key="contacts">
          <MobileContactsPage
            onChatSelect={(u) => {
              handleChatSelect(u);
            }}
          />
        </div>
      )}

      {/* Настройки */}
      {isMobile && activeTab === "settings" && (
        <div className="mobile-tab-page" key="settings">
          <MobileSettingsPage />
        </div>
      )}

      {/* Профиль */}
      {isMobile && activeTab === "profile" && (
        <div className="mobile-tab-page" key="profile">
          <ProfileModal isOpen={true} onClose={() => setActiveTab("chats")} />
        </div>
      )}

      <EmailVerificationBanner />

      {isMobile && !showChatOnMobile && (
        <MobileBottomNav
          activeTab={activeTab}
          onTabChange={handleTabChange}
          onSearchFocus={handleSearchFocus}
        />
      )}
    </div>
  );
}
