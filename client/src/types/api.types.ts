// Общие типы для API ответов
export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

// Типы для регистрации
export interface RegisterRequest {
  username: string;
  email: string;
  password: string;
  public_key: string;
  deviceFingerprint?: string;
}

export interface RegisterResponse {
  token: string;
  user: {
    username: string;
    email: string;
    email_verified: boolean;
    created_at: string;
    avatar_path?: string | null;
  };
}

// Типы для логина
export interface LoginRequest {
  username: string;
  password: string;
  deviceFingerprint?: string;
}

export interface LoginResponse {
  token: string;
  user: {
    username: string;
    email: string;
    email_verified: boolean;
    last_seen: string;
    avatar_path?: string | null;
  };
  status?: "pending_approval";
  pending_session_id?: string;
  message?: string;
}

// Типы для сообщений
export interface SendMessageRequest {
  recipient_username: string;
  encrypted_content: string;
  message_type?: "text" | "image" | "video" | "file" | "audio";
}

export interface SendMessageResponse {
  message_id: string;
  chat_id: string;
  created_at: string;
  status: "sent";
}

export interface GetMessagesResponse {
  messages: Message[];
  total: number;
  has_more: boolean;
}

export interface Message {
  id: string;
  sender_username: string;
  recipient_username: string;
  encrypted_content: string;
  message_type: string;
  created_at: string;
  delivered_at: string | null;
  read_at: string | null;
  edited_at?: string | null;
}

// Типы для Device Approval
export interface PendingLoginResponse {
  status: "pending_approval";
  pending_session_id: string;
  message: string;
}

export interface ApproveDeviceRequest {
  pending_session_id: string;
}

export interface ApproveDeviceResponse {
  approval_code: string;
  message: string;
}

export interface RejectDeviceRequest {
  pending_session_id: string;
}

export interface VerifyDeviceCodeRequest {
  pending_session_id: string;
  code: string;
}

export interface VerifyDeviceCodeResponse {
  token: string;
  user: {
    username: string;
    email: string;
    email_verified: boolean;
    avatar_path?: string | null;
  };
}

// Socket.IO события для Device Approval
export interface DeviceApprovalRequiredEvent {
  pending_session_id: string;
  device_info: {
    type: string;
    name: string;
    os: string;
  };
  ip_address: string;
  timestamp: string;
}

export interface DeviceApprovedEvent {
  pending_session_id: string;
  approval_code: string;
}

export interface DeviceRejectedEvent {
  pending_session_id: string;
  message: string;
}
