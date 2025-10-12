import Redis from 'ioredis'
import { env } from '../config/env.js'

const redis = new Redis(env.REDIS_URL)

redis.on('connect', () => {
  console.log('✅ Connected to Redis')
})

redis.on('error', (err) => {
  console.error('❌ Redis error:', err)
})

export class RedisService {
  /**
   * Сохранение кода подтверждения email (TTL 10 минут)
   */
  static async saveEmailCode(username: string, code: string): Promise<void> {
    const key = `email_verify:${username}`
    await redis.setex(key, 600, code) // 600 секунд = 10 минут
  }

  /**
   * Получение кода подтверждения
   */
  static async getEmailCode(username: string): Promise<string | null> {
    const key = `email_verify:${username}`
    return await redis.get(key)
  }

  /**
   * Удаление кода после успешного подтверждения
   */
  static async deleteEmailCode(username: string): Promise<void> {
    const key = `email_verify:${username}`
    await redis.del(key)
  }

  /**
   * Инкремент попыток ввода кода (максимум 5)
   */
  static async incrementEmailAttempts(username: string): Promise<number> {
    const key = `email_attempts:${username}`
    const attempts = await redis.incr(key)
    
    // Если первая попытка — установить TTL 10 минут
    if (attempts === 1) {
      await redis.expire(key, 600)
    }
    
    return attempts
  }

  /**
   * Получение количества попыток
   */
  static async getEmailAttempts(username: string): Promise<number> {
    const key = `email_attempts:${username}`
    const attempts = await redis.get(key)
    return attempts ? parseInt(attempts, 10) : 0
  }

  /**
   * Cooldown для повторной отправки кода (1 минута)
   */
  static async setEmailCooldown(username: string): Promise<void> {
    const key = `email_cooldown:${username}`
    await redis.setex(key, 60, '1') // 60 секунд
  }

  /**
   * Проверка cooldown
   */
  static async checkEmailCooldown(username: string): Promise<boolean> {
    const key = `email_cooldown:${username}`
    const exists = await redis.exists(key)
    return exists === 1
  }
}