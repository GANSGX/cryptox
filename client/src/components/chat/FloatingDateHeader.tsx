import { formatDateSeparator } from "@/utils/dateTime";

interface FloatingDateHeaderProps {
  date: string | null;
  visible: boolean;
}

/**
 * Плавающая плашка даты при скролле (как в Telegram)
 * Показывается вверху чата и меняется в зависимости от видимых сообщений
 */
export function FloatingDateHeader({ date, visible }: FloatingDateHeaderProps) {
  if (!date) return null;

  return (
    <div className={`floating-date-header ${visible ? "visible" : ""}`}>
      <span className="floating-date-text">{formatDateSeparator(date)}</span>
    </div>
  );
}
