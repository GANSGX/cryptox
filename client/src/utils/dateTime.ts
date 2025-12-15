/**
 * Утилиты для форматирования времени сообщений
 * Автоматическое определение timezone браузера пользователя
 */

/**
 * Проверяет, является ли дата сегодняшней
 */
function isToday(date: Date): boolean {
  const today = new Date();
  return (
    date.getDate() === today.getDate() &&
    date.getMonth() === today.getMonth() &&
    date.getFullYear() === today.getFullYear()
  );
}

/**
 * Проверяет, была ли дата вчера
 */
function isYesterday(date: Date): boolean {
  const yesterday = new Date();
  yesterday.setDate(yesterday.getDate() - 1);
  return (
    date.getDate() === yesterday.getDate() &&
    date.getMonth() === yesterday.getMonth() &&
    date.getFullYear() === yesterday.getFullYear()
  );
}

/**
 * Проверяет, в текущем ли году дата
 */
function isThisYear(date: Date): boolean {
  const today = new Date();
  return date.getFullYear() === today.getFullYear();
}

/**
 * Парсит дату от сервера, принудительно обрабатывая её как UTC
 * (если сервер шлёт без "Z" в конце)
 */
function parseServerDate(dateString: string): Date {
  // Если строка уже содержит timezone indicator (Z или +00:00), парсим напрямую
  if (
    dateString.endsWith("Z") ||
    dateString.includes("+") ||
    dateString.includes("-", 10)
  ) {
    return new Date(dateString);
  }

  // Если нет timezone - добавляем "Z" (UTC)
  // Пример: "2024-12-14T15:49:00" → "2024-12-14T15:49:00Z"
  const isoString = dateString.includes("T")
    ? dateString
    : dateString.replace(" ", "T");
  return new Date(`${isoString}Z`);
}

/**
 * Форматирует время сообщения для отображения в чате (только время!)
 *
 * @param dateString - ISO строка даты от сервера (UTC)
 * @returns Время "14:30"
 *
 * @example
 * formatMessageTime("2024-12-14T10:30:00Z") // "14:30"
 * formatMessageTime("2024-12-14T10:30:00") // "14:30" (парсится как UTC)
 */
export function formatMessageTime(dateString: string): string {
  const date = parseServerDate(dateString);
  const userLocale = navigator.language || "en-US";
  const userTimeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;

  // Всегда возвращаем только время с явным указанием timezone
  return new Intl.DateTimeFormat(userLocale, {
    hour: "2-digit",
    minute: "2-digit",
    timeZone: userTimeZone,
  }).format(date);
}

/**
 * Форматирует время для отображения в списке чатов (sidebar)
 *
 * Логика (упрощенная):
 * - Сегодня: "14:30"
 * - Вчера: "Вчера"
 * - Этот год: "12 дек"
 * - Старше: "12.12.2024"
 *
 * @param dateString - ISO строка даты от сервера (UTC)
 * @returns Отформатированная строка времени
 */
export function formatChatPreviewTime(dateString: string): string {
  const date = parseServerDate(dateString);
  const userLocale = navigator.language || "en-US";

  if (isToday(date)) {
    return new Intl.DateTimeFormat(userLocale, {
      hour: "2-digit",
      minute: "2-digit",
    }).format(date);
  }

  if (isYesterday(date)) {
    const rtf = new Intl.RelativeTimeFormat(userLocale, { numeric: "auto" });
    return rtf.format(-1, "day");
  }

  if (isThisYear(date)) {
    return new Intl.DateTimeFormat(userLocale, {
      day: "numeric",
      month: "short",
    }).format(date);
  }

  return new Intl.DateTimeFormat(userLocale, {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
  }).format(date);
}

/**
 * Форматирует полное время с датой для подсказок (tooltip)
 *
 * @param dateString - ISO строка даты от сервера (UTC)
 * @returns Полная дата и время "14 декабря 2024 г., 14:30"
 *
 * @example
 * formatFullDateTime("2024-12-14T10:30:00Z") // "14 декабря 2024 г., 14:30"
 */
export function formatFullDateTime(dateString: string): string {
  const date = parseServerDate(dateString);
  const userLocale = navigator.language || "en-US";

  return new Intl.DateTimeFormat(userLocale, {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

/**
 * Форматирует время в формате "только время" (для текущего дня)
 *
 * @param dateString - ISO строка даты от сервера (UTC)
 * @returns Время "14:30"
 */
export function formatTimeOnly(dateString: string): string {
  const date = parseServerDate(dateString);
  const userLocale = navigator.language || "en-US";

  return new Intl.DateTimeFormat(userLocale, {
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

/**
 * Форматирует дату для разделителя (плашки) между группами сообщений
 * Как в Telegram: "Сегодня", "Вчера", "11 декабря", "11 декабря 2023"
 *
 * @param dateString - ISO строка даты от сервера (UTC)
 * @returns Отформатированная дата для разделителя
 *
 * @example
 * formatDateSeparator("2024-12-14T10:30:00Z") // "Сегодня" (если сегодня 14 дек)
 * formatDateSeparator("2024-12-13T10:30:00Z") // "Вчера"
 * formatDateSeparator("2024-12-11T10:30:00Z") // "11 декабря"
 * formatDateSeparator("2023-05-15T10:30:00Z") // "15 мая 2023"
 */
export function formatDateSeparator(dateString: string): string {
  const date = parseServerDate(dateString);
  const userLocale = navigator.language || "en-US";

  if (isToday(date)) {
    // Сегодня - показываем "Сегодня" / "Today"
    const rtf = new Intl.RelativeTimeFormat(userLocale, { numeric: "auto" });
    return rtf.format(0, "day"); // "today" / "сегодня"
  }

  if (isYesterday(date)) {
    // Вчера - показываем "Вчера" / "Yesterday"
    const rtf = new Intl.RelativeTimeFormat(userLocale, { numeric: "auto" });
    return rtf.format(-1, "day"); // "yesterday" / "вчера"
  }

  if (isThisYear(date)) {
    // Этот год - показываем "11 декабря" / "December 11"
    return new Intl.DateTimeFormat(userLocale, {
      day: "numeric",
      month: "long",
    }).format(date);
  }

  // Старше года - показываем "11 декабря 2023" / "December 11, 2023"
  return new Intl.DateTimeFormat(userLocale, {
    day: "numeric",
    month: "long",
    year: "numeric",
  }).format(date);
}

/**
 * Проверяет, является ли дата той же, что и сравниваемая (игнорируя время)
 */
export function isSameDay(date1: Date, date2: Date): boolean {
  return (
    date1.getDate() === date2.getDate() &&
    date1.getMonth() === date2.getMonth() &&
    date1.getFullYear() === date2.getFullYear()
  );
}
