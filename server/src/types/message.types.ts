export interface Message {
  id: string;
  chat_id: string;
  sender_username: string;
  recipient_username: string;
  encrypted_content: string;
  message_type: "text" | "image" | "video" | "file" | "audio";
  media_id: string | null;
  reply_to_message_id: string | null;
  forwarded_from: string | null;
  created_at: Date;
  edited_at: Date | null;
  deleted_at: Date | null;
  delivered_at: Date | null;
  read_at: Date | null;
}

export interface CreateMessageData {
  sender_username: string;
  recipient_username: string;
  encrypted_content: string;
  message_type?: "text" | "image" | "video" | "file" | "audio";
}

export interface MessageStatus {
  message_id: string;
  status: "sent" | "delivered" | "read";
}
