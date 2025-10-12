export interface User {
  username: string
  email: string
  email_verified: boolean
}

export interface UserSearchResult {
  username: string
  avatar_path: string | null
  bio: string | null
  email_verified: boolean
}