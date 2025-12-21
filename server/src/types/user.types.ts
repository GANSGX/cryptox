export interface User {
  username: string;
  email: string;
  email_verified: boolean;

  salt: string;
  auth_token: string;
  encrypted_master_key: string;
  public_key: string;
  data_version: number;

  avatar_path: string | null;
  bio: string | null;
  status: string | null;
  birthday: string | null;

  status_privacy: "everyone" | "chats" | "friends" | "nobody";
  online_privacy: "everyone" | "chats" | "friends" | "nobody";
  typing_privacy: "everyone" | "chats" | "friends" | "nobody";

  created_at: Date;
  last_seen: Date;

  spam_score: number;
  is_banned: boolean;
}

export interface CreateUserData {
  username: string;
  email: string;
  salt: string;
  auth_token: string;
  encrypted_master_key: string;
  public_key: string;
}
