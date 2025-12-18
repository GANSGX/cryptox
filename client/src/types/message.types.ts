export interface Message {
  id: string;
  sender_username: string;
  recipient_username: string;
  encrypted_content: string;
  message_type: "text" | "image" | "video" | "file" | "audio";
  created_at: string;
  delivered_at: string | null;
  read_at: string | null;
  edited_at?: string | null;
  deleted_for_sender?: boolean;
  deleted_for_recipient?: boolean;
}

export interface ChatPreview {
  username: string;
  last_message: string;
  unread_count: number;
  timestamp: string;
}
