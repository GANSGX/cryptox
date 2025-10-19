import type { FastifyInstance } from 'fastify'
import { pool } from '../db/pool.js'
import { UserService } from '../services/user.service.js'
import { CryptoService } from '../services/crypto.service.js'
import { JwtService } from '../services/jwt.service.js'
import { EmailService } from '../services/email.service.js'
import { RedisService } from '../services/redis.service.js'
import {
  isValidUsername,
  isValidEmail,
  isValidPassword,
} from '../utils/crypto.js'
import type {
  RegisterRequest,
  RegisterResponse,
  LoginRequest,
  LoginResponse,
  SendVerificationCodeRequest,
  VerifyEmailRequest,
  VerifyEmailResponse,
  ApiResponse
} from '../types/api.types.js'

export async function authRoutes(fastify: FastifyInstance) {

  /**
   * POST /register
   * Регистрация нового пользователя
   */
  fastify.post<{
    Body: RegisterRequest
    Reply: ApiResponse<RegisterResponse>
  }>('/register', async (request, reply) => {
    const { username, email, password, public_key } = request.body

    // Валидация входных данных
    if (!username || !email || !password || !public_key) {
      return reply.code(400).send({
        success: false,
        error: 'Missing required fields',
      })
    }

    // Валидация username
    if (!isValidUsername(username)) {
      return reply.code(400).send({
        success: false,
        error: 'Invalid username format (3-30 chars, a-z, 0-9, _)',
      })
    }

    // Валидация email
    if (!isValidEmail(email)) {
      return reply.code(400).send({
        success: false,
        error: 'Invalid email format',
      })
    }

    // Валидация password
    if (!isValidPassword(password)) {
      return reply.code(400).send({
        success: false,
        error: 'Password must be at least 8 characters',
      })
    }

    // Проверка существования username
    const usernameExists = await UserService.usernameExists(username)
    if (usernameExists) {
      return reply.code(409).send({
        success: false,
        error: 'Username already taken',
      })
    }

    // Проверка существования email
    const emailExists = await UserService.emailExists(email)
    if (emailExists) {
      return reply.code(409).send({
        success: false,
        error: 'Email already registered',
      })
    }

    // Генерация криптографических ключей
    const keys = await CryptoService.generateUserKeys(password, email)

    // Создание пользователя в БД
    const user = await UserService.createUser({
      username,
      email,
      salt: keys.salt,
      auth_token: keys.authToken,
      encrypted_master_key: keys.encryptedMasterKey,
      public_key,
    })

    // Генерация JWT токена
    const token = JwtService.generate({
      username: user.username,
      email: user.email,
    })

    // Ответ
    return reply.code(201).send({
      success: true,
      data: {
        token,
        user: {
          username: user.username,
          email: user.email,
          email_verified: user.email_verified,
          created_at: user.created_at.toISOString(),
        },
      },
    })
  })

  /**
   * POST /login
   * Авторизация пользователя
   */
  fastify.post<{
    Body: LoginRequest
    Reply: ApiResponse<LoginResponse>
  }>('/login', async (request, reply) => {
    try {
      console.log('🔍 Login attempt:', request.body.username)

      const { username, password } = request.body

      // Валидация входных данных
      if (!username || !password) {
        return reply.code(400).send({
          success: false,
          error: 'Missing required fields',
        })
      }

      // Получение пользователя из БД
      const user = await UserService.getUserByUsername(username)
      console.log('📦 User from DB:', user ? 'found' : 'not found')

      if (!user) {
        return reply.code(401).send({
          success: false,
          error: 'Invalid username or password',
        })
      }

      // Проверка пароля через CryptoService
      const isPasswordValid = await CryptoService.verifyAuthToken(
        password,
        user.salt,
        user.auth_token
      )
      console.log('🔑 Password valid:', isPasswordValid)

      if (!isPasswordValid) {
        return reply.code(401).send({
          success: false,
          error: 'Invalid username or password',
        })
      }

      // Проверка бана
      if (user.is_banned) {
        return reply.code(403).send({
          success: false,
          error: 'Account is banned',
        })
      }

      // Обновление last_seen
      await UserService.updateLastSeen(username)

      // Генерация JWT токена
      const token = JwtService.generate({
        username: user.username,
        email: user.email,
      })

      // Сохранение сессии в БД
      try {
        await pool.query(
          `INSERT INTO sessions (username, device_info, ip_address, jwt_token, created_at, last_active, expires_at)
           VALUES ($1, $2, $3, $4, NOW(), NOW(), NOW() + INTERVAL '30 days')`,
          [
            username,
            JSON.stringify({
              type: 'browser',
              name: request.headers['user-agent']?.includes('YaBrowser') ? 'Yandex' :
                request.headers['user-agent']?.includes('Edg') ? 'Edge' :
                  request.headers['user-agent']?.includes('Firefox') ? 'Firefox' :
                    request.headers['user-agent']?.includes('Chrome') ? 'Chrome' :
                      request.headers['user-agent']?.includes('Safari') ? 'Safari' : 'Browser',
              os: request.headers['user-agent']?.includes('Windows') ? 'Windows' :
                request.headers['user-agent']?.includes('Mac') ? 'macOS' :
                  request.headers['user-agent']?.includes('Linux') ? 'Linux' : 'Unknown',
            }),
            request.ip,
            token,
          ]
        )
      } catch (error) {
        fastify.log.error({ error }, 'Failed to save session')
      }

      console.log('✅ Login successful, email_verified:', user.email_verified)

      // Ответ
      return reply.code(200).send({
        success: true,
        data: {
          token,
          user: {
            username: user.username,
            email: user.email,
            email_verified: user.email_verified,
            last_seen: user.last_seen.toISOString(),
          },
        },
      })
    } catch (error) {
      console.error('❌ Login error:', error)
      return reply.code(500).send({
        success: false,
        error: 'Internal server error',
      })
    }
  })

  /**
   * POST /send-verification-code
   * Отправка кода подтверждения на email
   */
  fastify.post<{
    Body: SendVerificationCodeRequest
    Reply: ApiResponse
  }>('/send-verification-code', async (request, reply) => {
    const { username } = request.body

    if (!username) {
      return reply.code(400).send({
        success: false,
        error: 'Missing username',
      })
    }

    // Получение пользователя
    const user = await UserService.getUserByUsername(username)

    if (!user) {
      return reply.code(404).send({
        success: false,
        error: 'User not found',
      })
    }

    // Если уже подтверждён
    if (user.email_verified) {
      return reply.code(400).send({
        success: false,
        error: 'Email already verified',
      })
    }

    // Проверка cooldown (1 минута)
    const hasCooldown = await RedisService.checkEmailCooldown(username)
    if (hasCooldown) {
      return reply.code(429).send({
        success: false,
        error: 'Please wait 1 minute before requesting a new code',
      })
    }

    // Генерация кода
    const code = CryptoService.generateEmailCode()

    // Сохранение в Redis (TTL 10 минут)
    await RedisService.saveEmailCode(username, code)

    // Установка cooldown
    await RedisService.setEmailCooldown(username)

    // Отправка email
    const emailSent = await EmailService.sendVerificationCode(user.email, code)

    if (!emailSent) {
      return reply.code(500).send({
        success: false,
        error: 'Failed to send email',
      })
    }

    return reply.code(200).send({
      success: true,
      message: 'Verification code sent to your email',
    })
  })

  /**
   * POST /verify-email
   * Проверка кода и подтверждение email
   */
  fastify.post<{
    Body: VerifyEmailRequest
    Reply: ApiResponse<VerifyEmailResponse>
  }>('/verify-email', async (request, reply) => {
    const { username, code } = request.body

    if (!username || !code) {
      return reply.code(400).send({
        success: false,
        error: 'Missing required fields',
      })
    }

    // Получение пользователя
    const user = await UserService.getUserByUsername(username)

    if (!user) {
      return reply.code(404).send({
        success: false,
        error: 'User not found',
      })
    }

    // Если уже подтверждён
    if (user.email_verified) {
      return reply.code(400).send({
        success: false,
        error: 'Email already verified',
      })
    }

    // Проверка количества попыток (максимум 5)
    const attempts = await RedisService.getEmailAttempts(username)
    if (attempts >= 5) {
      return reply.code(429).send({
        success: false,
        error: 'Too many attempts. Request a new code.',
      })
    }

    // Получение кода из Redis
    const storedCode = await RedisService.getEmailCode(username)

    if (!storedCode) {
      return reply.code(400).send({
        success: false,
        error: 'Code expired or not found. Request a new code.',
      })
    }

    // Проверка кода
    if (code !== storedCode) {
      await RedisService.incrementEmailAttempts(username)
      return reply.code(400).send({
        success: false,
        error: 'Invalid code',
      })
    }

    // Код правильный — обновляем пользователя
    await pool.query(
      'UPDATE users SET email_verified = true WHERE username = $1',
      [username]
    )

    // Удаляем код из Redis
    await RedisService.deleteEmailCode(username)

    return reply.code(200).send({
      success: true,
      data: {
        message: 'Email verified successfully',
        email_verified: true,
      },
    })
  })

  /**
   * POST /verify-password-send-code
   * Проверка пароля и отправка кода на текущую почту для смены email
   */
  fastify.post<{
    Body: { username: string; password: string }
    Reply: ApiResponse
  }>('/verify-password-send-code', async (request, reply) => {
    try {
      const { username, password } = request.body

      if (!username || !password) {
        return reply.code(400).send({
          success: false,
          error: 'Missing required fields',
        })
      }

      // Получение пользователя
      const user = await UserService.getUserByUsername(username)

      if (!user) {
        return reply.code(401).send({
          success: false,
          error: 'Invalid credentials',
        })
      }

      // Проверка пароля
      const isPasswordValid = await CryptoService.verifyAuthToken(
        password,
        user.salt,
        user.auth_token
      )

      if (!isPasswordValid) {
        return reply.code(401).send({
          success: false,
          error: 'Invalid credentials',
        })
      }

      // Проверка cooldown (1 минута)
      const hasCooldown = await RedisService.checkEmailCooldown(username)
      if (hasCooldown) {
        return reply.code(429).send({
          success: false,
          error: 'Please wait 1 minute before requesting a new code',
        })
      }

      // Генерация кода
      const code = CryptoService.generateEmailCode()

      // Сохранение в Redis с префиксом "change_email"
      await RedisService.saveChangeEmailCode(username, code)

      // Установка cooldown
      await RedisService.setEmailCooldown(username)

      // Отправка email на текущую почту
      const emailSent = await EmailService.sendVerificationCode(user.email, code)

      if (!emailSent) {
        return reply.code(500).send({
          success: false,
          error: 'Failed to send email',
        })
      }

      return reply.code(200).send({
        success: true,
        message: 'Verification code sent to your current email',
      })
    } catch (error) {
      console.error('❌ verify-password-send-code error:', error)
      return reply.code(500).send({
        success: false,
        error: 'Internal server error',
      })
    }
  })

  /**
   * POST /verify-current-email-code
   * Проверка кода с текущей почты
   */
  fastify.post<{
    Body: { username: string; code: string }
    Reply: ApiResponse
  }>('/verify-current-email-code', async (request, reply) => {
    try {
      const { username, code } = request.body

      if (!username || !code) {
        return reply.code(400).send({
          success: false,
          error: 'Missing required fields',
        })
      }

      // Получение кода из Redis
      const storedCode = await RedisService.getChangeEmailCode(username)

      if (!storedCode) {
        return reply.code(400).send({
          success: false,
          error: 'Code expired or not found. Request a new code.',
        })
      }

      // Проверка кода
      if (code !== storedCode) {
        return reply.code(400).send({
          success: false,
          error: 'Invalid code',
        })
      }

      // Код правильный - сохраняем флаг что можно менять email
      await RedisService.setChangeEmailVerified(username)

      return reply.code(200).send({
        success: true,
        message: 'Code verified successfully',
      })
    } catch (error) {
      console.error('❌ verify-current-email-code error:', error)
      return reply.code(500).send({
        success: false,
        error: 'Internal server error',
      })
    }
  })

  /**
   * POST /change-email
   * Изменение email на новый (неподтвержденный)
   */
  fastify.post<{
    Body: { username: string; new_email: string }
    Reply: ApiResponse
  }>('/change-email', async (request, reply) => {
    try {
      const { username, new_email } = request.body

      if (!username || !new_email) {
        return reply.code(400).send({
          success: false,
          error: 'Missing required fields',
        })
      }

      // Валидация email
      if (!isValidEmail(new_email)) {
        return reply.code(400).send({
          success: false,
          error: 'Invalid email format',
        })
      }

      // Проверка что прошёл верификацию кода
      const isVerified = await RedisService.isChangeEmailVerified(username)

      if (!isVerified) {
        return reply.code(403).send({
          success: false,
          error: 'Please verify your current email first',
        })
      }

      // Проверка что новый email не занят
      const emailExists = await UserService.emailExists(new_email)
      if (emailExists) {
        return reply.code(409).send({
          success: false,
          error: 'Email already registered',
        })
      }

      // Обновление email в БД (устанавливаем email_verified = false)
      await pool.query(
        'UPDATE users SET email = $1, email_verified = false WHERE username = $2',
        [new_email, username]
      )

      // Удаляем флаги из Redis
      await RedisService.deleteChangeEmailCode(username)
      await RedisService.deleteChangeEmailVerified(username)

      return reply.code(200).send({
        success: true,
        message: 'Email changed successfully',
      })
    } catch (error) {
      console.error('❌ change-email error:', error)
      return reply.code(500).send({
        success: false,
        error: 'Internal server error',
      })
    }
  })
}