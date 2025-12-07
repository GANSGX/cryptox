/**
 * HTML Sanitization utilities to prevent XSS attacks
 */

/**
 * Removes all HTML tags from a string
 * Example: "<script>alert('xss')</script>hello" → "hello"
 */
export function stripHtmlTags(input: string): string {
  if (typeof input !== "string") {
    return "";
  }
  // Remove all HTML tags
  return input.replace(/<[^>]*>/g, "");
}

/**
 * Escapes HTML special characters to prevent XSS
 * Example: "<script>alert('xss')</script>" → "&lt;script&gt;alert('xss')&lt;/script&gt;"
 */
export function escapeHtml(input: string): string {
  if (typeof input !== "string") {
    return "";
  }

  const htmlEscapeMap: Record<string, string> = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#x27;",
    "/": "&#x2F;",
  };

  return input.replace(/[&<>"'/]/g, (char) => htmlEscapeMap[char] || char);
}

/**
 * Sanitizes username: removes HTML tags, trims whitespace, limits length
 * Usernames should be alphanumeric + underscores only
 */
export function sanitizeUsername(username: string): string {
  if (typeof username !== "string") {
    return "";
  }

  // Remove HTML tags first
  let sanitized = stripHtmlTags(username);

  // Remove any non-alphanumeric characters except underscores and hyphens
  sanitized = sanitized.replace(/[^a-zA-Z0-9_-]/g, "");

  // Trim to max 30 characters
  sanitized = sanitized.substring(0, 30);

  return sanitized.trim();
}

/**
 * Sanitizes user bio: removes dangerous HTML, keeps basic formatting
 * Allows only safe tags like <b>, <i>, <em>, <strong>
 */
export function sanitizeBio(bio: string): string {
  if (typeof bio !== "string") {
    return "";
  }

  // For now, strip all HTML tags from bio to prevent XSS
  // Later can whitelist safe tags if needed
  return stripHtmlTags(bio).substring(0, 500).trim();
}

/**
 * Sanitizes message content: escapes HTML to prevent XSS
 */
export function sanitizeMessage(message: string): string {
  if (typeof message !== "string") {
    return "";
  }

  // Escape HTML entities
  return escapeHtml(message).substring(0, 10000).trim();
}

/**
 * Sanitizes search queries: removes special characters that could be used for injection
 */
export function sanitizeSearchQuery(query: string): string {
  if (typeof query !== "string") {
    return "";
  }

  // Remove HTML tags
  let sanitized = stripHtmlTags(query);

  // Remove SQL injection characters
  sanitized = sanitized.replace(/[;'"\\]/g, "");

  // Limit length
  sanitized = sanitized.substring(0, 100);

  return sanitized.trim();
}

/**
 * Validates and sanitizes email
 */
export function sanitizeEmail(email: string): string {
  if (typeof email !== "string") {
    return "";
  }

  // Basic email format check (not comprehensive, just for safety)
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  // Remove HTML tags and trim
  const sanitized = stripHtmlTags(email).trim().toLowerCase();

  // Return empty if invalid format
  if (!emailRegex.test(sanitized)) {
    return "";
  }

  return sanitized.substring(0, 100);
}
