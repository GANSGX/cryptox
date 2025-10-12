import { pool } from '../db/pool.js'
import type { User, CreateUserData } from '../types/user.types.js'

export class UserService {
  /**
   * Проверка существует ли username
   */
  static async usernameExists(username: string): Promise<boolean> {
    const result = await pool.query(
      'SELECT 1 FROM users WHERE username = $1',
      [username.toLowerCase()]
    )
    return result.rows.length > 0
  }

  /**
   * Проверка существует ли email
   */
  static async emailExists(email: string): Promise<boolean> {
    const result = await pool.query(
      'SELECT 1 FROM users WHERE email = $1',
      [email.toLowerCase()]
    )
    return result.rows.length > 0
  }

  /**
   * Создание пользователя
   */
  static async createUser(data: CreateUserData): Promise<User> {
    const result = await pool.query(
      `INSERT INTO users (
        username, 
        email, 
        salt, 
        auth_token, 
        encrypted_master_key, 
        public_key,
        data_version
      ) VALUES ($1, $2, $3, $4, $5, $6, 2)
      RETURNING *`,
      [
        data.username.toLowerCase(),
        data.email.toLowerCase(),
        data.salt,
        data.auth_token,
        data.encrypted_master_key,
        data.public_key,
      ]
    )

    return result.rows[0]
  }

  /**
   * Получение пользователя по username
   */
  static async getUserByUsername(username: string): Promise<User | null> {
    const result = await pool.query(
      'SELECT * FROM users WHERE username = $1',
      [username.toLowerCase()]
    )

    return result.rows[0] || null
  }

  /**
   * Получение пользователя по email
   */
  static async getUserByEmail(email: string): Promise<User | null> {
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email.toLowerCase()]
    )

    return result.rows[0] || null
  }

  /**
   * Обновление last_seen
   */
  static async updateLastSeen(username: string): Promise<void> {
    await pool.query(
      'UPDATE users SET last_seen = NOW() WHERE username = $1',
      [username.toLowerCase()]
    )
  }

  /**
   * Поиск пользователей по username
   */
  static async searchUsers(query: string, limit: number = 20): Promise<any[]> {
    const result = await pool.query(
      `SELECT 
        username, 
        avatar_path, 
        bio, 
        email_verified
      FROM users 
      WHERE 
        username ILIKE $1 
        AND is_banned = false
      ORDER BY 
        CASE WHEN username = $2 THEN 0 ELSE 1 END,
        username
      LIMIT $3`,
      [`%${query.toLowerCase()}%`, query.toLowerCase(), limit]
    )

    return result.rows
  }
}