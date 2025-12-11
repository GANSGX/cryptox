import { Check } from "lucide-react";

interface MessageStatusProps {
  createdAt: string;
  deliveredAt: string | null;
  readAt: string | null;
  isSent: boolean; // true если это моё отправленное сообщение
}

export function MessageStatus({
  deliveredAt,
  readAt,
  isSent,
}: MessageStatusProps) {
  // Не показываем статус для полученных сообщений
  if (!isSent) {
    return null;
  }

  // 2 синие галочки - прочитано
  if (readAt) {
    return (
      <span className="message-status read double-check" title="Read">
        <Check size={16} className="check-1" />
        <Check size={16} className="check-2" />
      </span>
    );
  }

  // 2 серые галочки - доставлено
  if (deliveredAt) {
    return (
      <span className="message-status delivered double-check" title="Delivered">
        <Check size={16} className="check-1" />
        <Check size={16} className="check-2" />
      </span>
    );
  }

  // 1 серая галочка - отправлено
  return (
    <span className="message-status sent" title="Sent">
      <Check size={16} />
    </span>
  );
}
