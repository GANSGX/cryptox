import { formatDateSeparator } from "@/utils/dateTime";

interface DateSeparatorProps {
  date: string;
}

/**
 * Разделитель дат между группами сообщений (как в Telegram)
 * Отображает плашку: "Сегодня", "Вчера", "11 декабря" и т.д.
 */
export function DateSeparator({ date }: DateSeparatorProps) {
  return (
    <div className="date-separator" data-date={date}>
      <span className="date-separator-text">{formatDateSeparator(date)}</span>
    </div>
  );
}
