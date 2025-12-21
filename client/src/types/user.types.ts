export interface User {
  username: string;
  email: string;
  email_verified: boolean;
  avatar_path?: string | null;
}

export interface UserSearchResult {
  username: string;
  avatar_path: string | null;
  bio: string | null;
  email_verified: boolean;
}
