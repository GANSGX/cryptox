import { useChatStore } from "@/store/chatStore";
import { useAuthStore } from "@/store/authStore";
import "./MobileContactsPage.css";

interface Props {
  onChatSelect: (username: string) => void;
}

export function MobileContactsPage({ onChatSelect }: Props) {
  const { user } = useAuthStore();
  const { contacts } = useChatStore();

  const filtered = contacts.filter((c) => c.username !== user?.username);

  // Группируем по первой букве
  const grouped: Record<string, typeof filtered> = {};
  filtered.forEach((c) => {
    const letter = c.username[0].toUpperCase();
    if (!grouped[letter]) grouped[letter] = [];
    grouped[letter].push(c);
  });
  const letters = Object.keys(grouped).sort();

  return (
    <div className="mcp-page">
      <h1 className="mcp-title">Contacts</h1>

      {letters.length === 0 ? (
        <p className="mcp-empty">No contacts yet</p>
      ) : (
        letters.map((letter) => (
          <div key={letter} className="mcp-group">
            <span className="mcp-letter">{letter}</span>
            <div className="mcp-group-card">
              {grouped[letter].map((contact, i) => (
                <button
                  key={contact.username}
                  className="mcp-row"
                  onClick={() => onChatSelect(contact.username)}
                >
                  <div className="mcp-avatar">
                    {contact.avatar_path ? (
                      <img
                        src={`http://localhost:3001${contact.avatar_path}`}
                        alt=""
                      />
                    ) : (
                      contact.username[0].toUpperCase()
                    )}
                  </div>
                  <span className="mcp-name">{contact.username}</span>
                  {i < grouped[letter].length - 1 && (
                    <span className="mcp-sep" />
                  )}
                </button>
              ))}
            </div>
          </div>
        ))
      )}
    </div>
  );
}
