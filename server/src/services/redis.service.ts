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
    await redis.setex(key, 30, '1') // 30 секунд
  }

  /**
   * Проверка cooldown
   */
  static async checkEmailCooldown(username: string): Promise<boolean> {
    const key = `email_cooldown:${username}`
    const exists = await redis.exists(key)
    return exists === 1
  }

  /**
   * Сохранение кода для смены email (TTL 10 минут)
   */
  static async saveChangeEmailCode(username: string, code: string): Promise<void> {
    const key = `change_email:${username}`
    await redis.setex(key, 600, code)
  }

  /**
   * Получение кода для смены email
   */
  static async getChangeEmailCode(username: string): Promise<string | null> {
    const key = `change_email:${username}`
    return await redis.get(key)
  }

  /**
   * Удаление кода смены email
   */
  static async deleteChangeEmailCode(username: string): Promise<void> {
    const key = `change_email:${username}`
    await redis.del(key)
  }

  /**
   * Установка флага успешной верификации текущей почты (TTL 5 минут)
   */
  static async setChangeEmailVerified(username: string): Promise<void> {
    const key = `change_email_verified:${username}`
    await redis.setex(key, 300, 'true')
  }

  /**
   * Проверка флага верификации текущей почты
   */
  static async isChangeEmailVerified(username: string): Promise<boolean> {
    const key = `change_email_verified:${username}`
    const exists = await redis.exists(key)
    return exists === 1
  }

  /**
   * Удаление флага верификации
   */
  static async deleteChangeEmailVerified(username: string): Promise<void> {
    const key = `change_email_verified:${username}`
    await redis.del(key)
  }

  /**
   * Password Reset Rate Limiting (по EMAIL!)
   * Максимум 5 попыток в час
   */

  /**
   * Получение количества попыток сброса пароля по email
   */
  static async getPasswordResetAttempts(email: string): Promise<number> {
    const key = `password_reset_attempts:${email}`
    const attempts = await redis.get(key)
    return attempts ? parseInt(attempts, 10) : 0
  }

  /**
   * Инкремент попыток сброса пароля (TTL 1 час)
   */
  static async incrementPasswordResetAttempts(email: string): Promise<number> {
    const key = `password_reset_attempts:${email}`
    const attempts = await redis.incr(key)

    // Если первая попытка — установить TTL 1 час
    if (attempts === 1) {
      await redis.expire(key, 3600) // 3600 секунд = 1 час
    }

    return attempts
  }

  /**
   * Cooldown для повторной отправки письма восстановления (1 минута)
   */
  static async setPasswordResetCooldown(email: string): Promise<void> {
    const key = `password_reset_cooldown:${email}`
    await redis.setex(key, 60, '1') // 60 секунд = 1 минута
  }

  /**
   * Проверка cooldown для сброса пароля
   */
  static async checkPasswordResetCooldown(email: string): Promise<boolean> {
    const key = `password_reset_cooldown:${email}`
    const exists = await redis.exists(key)
    return exists === 1
  }
}