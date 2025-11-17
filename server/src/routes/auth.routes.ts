import type { FastifyInstance } from 'fastify'
import { pool } from '../db/pool.js'
import { UserService } from '../services/user.service.js'
import { CryptoService } from '../services/crypto.service.js'
import { JwtService } from '../services/jwt.service.js'
import { EmailService } from '../services/email.service.js'
import { RedisService } from '../services/redis.service.js'
import { authMiddleware } from '../middleware/auth.middleware.js'
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
    const { username, email, password, public_key, deviceFingerprint } = request.body

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

    // Создаем первую сессию (всегда is_primary = true при регистрации)
    try {
      const userAgent = request.headers['user-agent'] || 'Unknown'
      let os = 'Unknown'

      if (userAgent) {
        if (userAgent.includes('Windows')) {
          os = 'Windows'
        } else if (userAgent.includes('Mac')) {
          os = 'macOS'
        } else if (userAgent.includes('Android')) {
          os = 'Android'
        } else if (userAgent.includes('iPhone') || userAgent.includes('iPad')) {
          os = 'iOS'
        } else if (userAgent.includes('Linux')) {
          os = 'Linux'
        }
      }

      const deviceInfo = {
        type: 'browser',
        name: userAgent.includes('YaBrowser') || userAgent.includes('YaBro') ? 'Yandex' :
          userAgent.includes('Edg') ? 'Edge' :
            userAgent.includes('Firefox') ? 'Firefox' :
              userAgent.includes('Chrome') ? 'Chrome' :
                userAgent.includes('Safari') ? 'Safari' : 'Browser',
        os: os,
      }

      const deviceInfoStr = JSON.stringify(deviceInfo)

      await pool.query(
        `INSERT INTO sessions (username, device_info, ip_address, jwt_token, device_fingerprint, is_primary, created_at, last_active, expires_at)
         VALUES ($1, $2, $3, $4, $5, true, NOW(), NOW(), NOW() + INTERVAL '30 days')`,
        [user.username, deviceInfoStr, request.ip, token, deviceFingerprint || null]
      )

      console.log('✅ First session created for new user')
    } catch (error) {
      fastify.log.error({ error }, 'Failed to create first session')
    }

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

      const { username, password, deviceFingerprint } = request.body

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
        const userAgent = request.headers['user-agent'] || ''
        const secChUaPlatform = request.headers['sec-ch-ua-platform'] as string || ''

        // Улучшенное определение ОС
        // Сначала проверяем sec-ch-ua-platform (более надежный источник)
        let os = 'Unknown'
        if (secChUaPlatform) {
          const platformLower = secChUaPlatform.toLowerCase().replace(/"/g, '')
          if (platformLower.includes('windows')) {
            os = 'Windows'
          } else if (platformLower.includes('macos') || platformLower.includes('mac os')) {
            os = 'macOS'
          } else if (platformLower.includes('linux')) {
            os = 'Linux'
          } else if (platformLower.includes('android')) {
            os = 'Android'
          } else if (platformLower.includes('ios')) {
            os = 'iOS'
          }
        }

        // Fallback на User-Agent если sec-ch-ua-platform не помог
        if (os === 'Unknown') {
          if (userAgent.includes('Windows NT') || userAgent.includes('Win64') || userAgent.includes('Win32')) {
            os = 'Windows'
          } else if (userAgent.includes('Mac OS X') || userAgent.includes('Macintosh')) {
            os = 'macOS'
          } else if (userAgent.includes('Android')) {
            os = 'Android'
          } else if (userAgent.includes('iPhone') || userAgent.includes('iPad')) {
            os = 'iOS'
          } else if (userAgent.includes('Linux')) {
            os = 'Linux'
          }
        }

        const deviceInfo = {
          type: 'browser',
          name: userAgent.includes('YaBrowser') || userAgent.includes('YaBro') ? 'Yandex' :
            userAgent.includes('Edg') ? 'Edge' :
              userAgent.includes('Firefox') ? 'Firefox' :
                userAgent.includes('Chrome') ? 'Chrome' :
                  userAgent.includes('Safari') ? 'Safari' : 'Browser',
          os: os,
        }

        const deviceInfoStr = JSON.stringify(deviceInfo)

        // ===== НОВАЯ ЛОГИКА С FINGERPRINT =====
        if (deviceFingerprint) {
          // Проверяем, есть ли активная сессия с таким fingerprint
          const existingSession = await pool.query(
            `SELECT id, is_primary FROM sessions
             WHERE username = $1 AND device_fingerprint = $2 AND expires_at > NOW()
             LIMIT 1`,
            [username, deviceFingerprint]
          )

          if (existingSession.rows.length > 0) {
            // Сессия с таким fingerprint существует - ОБНОВЛЯЕМ её
            const session = existingSession.rows[0]
            console.log('♻️  Updating existing session:', session.id)

            await pool.query(
              `UPDATE sessions
               SET jwt_token = $1, last_active = NOW(), expires_at = NOW() + INTERVAL '30 days', device_info = $2, ip_address = $3
               WHERE id = $4`,
              [token, deviceInfoStr, request.ip, session.id]
            )

            console.log('✅ Session updated, is_primary:', session.is_primary)
          } else {
            // Сессии с таким fingerprint НЕТ - проверяем was_primary
            // Была ли раньше primary сессия с таким fingerprint (даже истекшая)?
            const wasPrimaryCheck = await pool.query(
              `SELECT COUNT(*) as count FROM sessions
               WHERE username = $1 AND device_fingerprint = $2 AND is_primary = TRUE`,
              [username, deviceFingerprint]
            )

            const wasPrimary = parseInt(wasPrimaryCheck.rows[0].count) > 0

            // Проверяем было ли ВООБЩЕ это устройство (любая сессия с этим fingerprint)
            const wasKnownDeviceCheck = await pool.query(
              `SELECT COUNT(*) as count FROM sessions
               WHERE username = $1 AND device_fingerprint = $2`,
              [username, deviceFingerprint]
            )

            const wasKnownDevice = parseInt(wasKnownDeviceCheck.rows[0].count) > 0

            // Проверяем есть ли АКТИВНОЕ главное устройство (у других fingerprint)
            const activePrimaryCheck = await pool.query(
              `SELECT COUNT(*) as count FROM sessions
               WHERE username = $1 AND is_primary = TRUE AND expires_at > NOW()`,
              [username]
            )

            const hasActivePrimary = parseInt(activePrimaryCheck.rows[0].count) > 0

            // ===== DEVICE APPROVAL LOGIC =====
            // Если устройство СОВСЕМ НОВОЕ (никогда не было) И есть primary устройство → требуется подтверждение
            if (!wasKnownDevice && hasActivePrimary) {
              console.log('🚨 NEW DEVICE detected, requiring approval from primary device')

              // Генерируем 6-значный код
              const approvalCode = Math.floor(100000 + Math.random() * 900000).toString()

              // Создаем pending_session
              const pendingSession = await pool.query(
                `INSERT INTO pending_sessions (username, device_fingerprint, device_info, ip_address, approval_code, status, created_at, expires_at)
                 VALUES ($1, $2, $3, $4, $5, 'pending', NOW(), NOW() + INTERVAL '5 minutes')
                 RETURNING id`,
                [username, deviceFingerprint, deviceInfoStr, request.ip, approvalCode]
              )

              const pendingSessionId = pendingSession.rows[0].id

              console.log('✅ Pending session created:', pendingSessionId, 'code:', approvalCode)

              // Отправляем Socket.IO уведомление на primary device
              fastify.io.to(username).emit('device:approval_required', {
                pending_session_id: pendingSessionId,
                device_info: deviceInfo,
                ip_address: request.ip,
                timestamp: new Date().toISOString(),
              })

              console.log('📢 Sent device approval notification to primary device')

              // Возвращаем клиенту статус "pending_approval"
              return reply.send({
                success: true,
                data: {
                  status: 'pending_approval',
                  pending_session_id: pendingSessionId,
                  message: 'Device approval required. Check your primary device.',
                },
              })
            }

            // Если была primary ИЛИ нет активной primary - делаем новую primary
            const isPrimary = wasPrimary || !hasActivePrimary

            console.log('🆕 Creating new session, is_primary:', isPrimary, '(wasPrimary:', wasPrimary, ', hasActivePrimary:', hasActivePrimary, ')')

            // Удаляем истекшие сессии с таким же fingerprint
            await pool.query(
              `DELETE FROM sessions
               WHERE username = $1 AND device_fingerprint = $2 AND expires_at <= NOW()`,
              [username, deviceFingerprint]
            )

            // Удаляем старые сессии если их больше 10
            const sessionsCount = await pool.query(
              'SELECT COUNT(*) as count FROM sessions WHERE username = $1 AND expires_at > NOW()',
              [username]
            )
            const currentSessionsCount = parseInt(sessionsCount.rows[0].count)

            if (currentSessionsCount >= 10) {
              await pool.query(
                `DELETE FROM sessions
                 WHERE id IN (
                   SELECT id FROM sessions
                   WHERE username = $1 AND expires_at > NOW() AND is_primary = FALSE
                   ORDER BY last_active ASC
                   LIMIT $2
                 )`,
                [username, currentSessionsCount - 9]
              )
            }

            // Создаем новую сессию
            await pool.query(
              `INSERT INTO sessions (username, device_info, ip_address, jwt_token, device_fingerprint, is_primary, created_at, last_active, expires_at)
               VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), NOW() + INTERVAL '30 days')`,
              [username, deviceInfoStr, request.ip, token, deviceFingerprint, isPrimary]
            )
          }
        } else {
          // ===== FALLBACK: Старая логика БЕЗ fingerprint =====
          console.log('⚠️  No fingerprint provided, using legacy session creation')

          const primaryCheck = await pool.query(
            'SELECT COUNT(*) as count FROM sessions WHERE username = $1 AND is_primary = TRUE AND expires_at > NOW()',
            [username]
          )
          const hasActivePrimaryDevice = parseInt(primaryCheck.rows[0].count) > 0

          if (!hasActivePrimaryDevice) {
            await pool.query(
              'DELETE FROM sessions WHERE username = $1 AND is_primary = TRUE AND expires_at <= NOW()',
              [username]
            )
          }

          const isPrimary = !hasActivePrimaryDevice

          const sessionsCount = await pool.query(
            'SELECT COUNT(*) as count FROM sessions WHERE username = $1 AND expires_at > NOW()',
            [username]
          )
          const currentSessionsCount = parseInt(sessionsCount.rows[0].count)

          if (currentSessionsCount >= 10) {
            await pool.query(
              `DELETE FROM sessions
               WHERE id IN (
                 SELECT id FROM sessions
                 WHERE username = $1 AND expires_at > NOW() AND is_primary = FALSE
                 ORDER BY last_active ASC
                 LIMIT $2
               )`,
              [username, currentSessionsCount - 9]
            )
          }

          await pool.query(
            `INSERT INTO sessions (username, device_info, ip_address, jwt_token, device_fingerprint, is_primary, created_at, last_active, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW(), NOW() + INTERVAL '30 days')`,
            [username, deviceInfoStr, request.ip, token, null, isPrimary]
          )
        }

        // Уведомляем все устройства пользователя об обновлении сессий
        if (fastify.io) {
          fastify.io.to(username).emit('sessions:updated')
        }

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
   * POST /logout
   * Выход из аккаунта (удаление текущей сессии)
   */
  fastify.post('/logout', async (request, reply) => {
    try {
      const authHeader = request.headers.authorization

      if (!authHeader) {
        return reply.code(401).send({
          success: false,
          error: 'Missing authorization header',
        })
      }

      const token = authHeader.replace('Bearer ', '')

      // Проверяем токен и получаем username
      const payload = JwtService.verify(token)

      if (!payload) {
        return reply.code(401).send({
          success: false,
          error: 'Invalid token',
        })
      }

      // Удаляем сессию из БД
      const result = await pool.query(
        'DELETE FROM sessions WHERE jwt_token = $1 RETURNING id',
        [token]
      )

      if (result.rowCount > 0) {
        // Уведомляем все устройства пользователя об обновлении списка сессий
        if (fastify.io) {
          fastify.io.to(payload.username).emit('sessions:updated')
        }
      }

      return reply.code(200).send({
        success: true,
        message: 'Logged out successfully',
      })
    } catch (error) {
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

  /**
   * POST /forgot-password
   * Запрос на восстановление пароля
   * ВАЖНО: Всегда возвращает успех, даже если email не найден (защита от enumeration)
   */
  fastify.post<{
    Body: { email: string }
  }>('/forgot-password', async (request, reply) => {
    try {
      const { email } = request.body

      // Валидация email
      if (!email || !isValidEmail(email)) {
        // Даже при невалидном email возвращаем общее сообщение
        return reply.code(200).send({
          success: true,
          message: 'If a user with this email exists, a password recovery email has been sent.',
        })
      }

      // Проверка rate limiting (максимум 5 попыток в час)
      const attempts = await RedisService.getPasswordResetAttempts(email)
      if (attempts >= 5) {
        return reply.code(429).send({
          success: false,
          error: 'Too many password reset requests. Please try again later.',
        })
      }

      // Проверка cooldown (1 минута между запросами)
      const hasCooldown = await RedisService.checkPasswordResetCooldown(email)
      if (hasCooldown) {
        return reply.code(429).send({
          success: false,
          error: 'Please wait before requesting another password reset email.',
        })
      }

      // Поиск пользователя по email
      const result = await pool.query(
        'SELECT username, email_verified FROM users WHERE email = $1',
        [email]
      )

      // Инкремент попыток (даже если пользователь не найден)
      await RedisService.incrementPasswordResetAttempts(email)

      // ВСЕГДА возвращаем успех (защита от enumeration)
      // Но отправляем письмо только если пользователь найден И email подтвержден
      if (result.rows.length > 0 && result.rows[0].email_verified) {
        const username = result.rows[0].username

        // Создаем токен восстановления (UUID, expires через 1 час)
        const tokenResult = await pool.query(
          `INSERT INTO password_recovery (username, expires_at)
           VALUES ($1, NOW() + INTERVAL '1 hour')
           RETURNING token`,
          [username]
        )

        const token = tokenResult.rows[0].token

        // Отправляем письмо
        const emailSent = await EmailService.sendPasswordRecovery(email, token)

        if (emailSent) {
          // Устанавливаем cooldown только при успешной отправке
          await RedisService.setPasswordResetCooldown(email)
        }
      }

      // ВСЕГДА возвращаем одинаковый ответ
      return reply.code(200).send({
        success: true,
        message: 'If a user with this email exists, a password recovery email has been sent.',
      })
    } catch (error) {
      console.error('❌ forgot-password error:', error)
      return reply.code(500).send({
        success: false,
        error: 'Internal server error',
      })
    }
  })

  /**
   * POST /reset-password
   * Сброс пароля по токену из email
   */
  fastify.post<{
    Body: { token: string; newPassword: string }
  }>('/reset-password', async (request, reply) => {
    try {
      const { token, newPassword } = request.body

      // Валидация
      if (!token || !newPassword) {
        return reply.code(400).send({
          success: false,
          error: 'Missing required fields',
        })
      }

      // Валидация пароля
      if (!isValidPassword(newPassword)) {
        return reply.code(400).send({
          success: false,
          error: 'Password must be at least 8 characters',
        })
      }

      // Проверка токена в БД
      const tokenResult = await pool.query(
        `SELECT username, used, expires_at
         FROM password_recovery
         WHERE token = $1`,
        [token]
      )

      if (tokenResult.rows.length === 0) {
        return reply.code(400).send({
          success: false,
          error: 'Invalid or expired recovery token',
        })
      }

      const recovery = tokenResult.rows[0]

      // Проверка что токен не использован
      if (recovery.used) {
        return reply.code(400).send({
          success: false,
          error: 'This recovery token has already been used',
        })
      }

      // Проверка что токен не истёк
      if (new Date(recovery.expires_at) < new Date()) {
        return reply.code(400).send({
          success: false,
          error: 'Recovery token has expired',
        })
      }

      const username = recovery.username

      // Получаем email пользователя (нужен для emailRecoveryKey)
      const userResult = await pool.query(
        'SELECT email FROM users WHERE username = $1',
        [username]
      )

      if (userResult.rows.length === 0) {
        return reply.code(404).send({
          success: false,
          error: 'User not found',
        })
      }

      const email = userResult.rows[0].email

      // Генерируем новые ключи с новым паролем
      const keys = await CryptoService.generateUserKeys(newPassword, email)

      // Обновляем ТОЛЬКО salt и auth_token (encrypted_master_key остается без изменений!)
      await pool.query(
        `UPDATE users
         SET salt = $1, auth_token = $2
         WHERE username = $3`,
        [keys.salt, keys.authToken, username]
      )

      // Помечаем токен как использованный
      await pool.query(
        'UPDATE password_recovery SET used = true WHERE token = $1',
        [token]
      )

      // Удаляем ВСЕ сессии пользователя (т.к. пароль изменён)
      await pool.query(
        'DELETE FROM sessions WHERE username = $1',
        [username]
      )

      // Уведомляем через Socket.IO о завершении всех сессий
      if (fastify.io) {
        fastify.io.to(username).emit('session:terminated', {
          message: 'Your password has been changed. Please log in again.',
        })
      }

      return reply.code(200).send({
        success: true,
        message: 'Password has been reset successfully. Please log in with your new password.',
      })
    } catch (error) {
      console.error('❌ reset-password error:', error)
      return reply.code(500).send({
        success: false,
        error: 'Internal server error',
      })
    }
  })

  /**
   * POST /change-password
   * Смена пароля изнутри приложения (требует аутентификации)
   */
  fastify.post<{
    Body: { currentPassword: string; newPassword: string }
  }>('/change-password', {
    preHandler: authMiddleware
  }, async (request, reply) => {
    try {
      const { currentPassword, newPassword } = request.body
      const username = (request as any).user.username
      const currentToken = request.headers.authorization?.replace('Bearer ', '')

      // Валидация
      if (!currentPassword || !newPassword) {
        return reply.code(400).send({
          success: false,
          error: 'Missing required fields',
        })
      }

      // Валидация нового пароля
      if (!isValidPassword(newPassword)) {
        return reply.code(400).send({
          success: false,
          error: 'New password must be at least 8 characters',
        })
      }

      // Проверка что пароли разные
      if (currentPassword === newPassword) {
        return reply.code(400).send({
          success: false,
          error: 'New password must be different from current password',
        })
      }

      // Получаем пользователя
      const userResult = await pool.query(
        'SELECT email, salt, auth_token FROM users WHERE username = $1',
        [username]
      )

      if (userResult.rows.length === 0) {
        return reply.code(404).send({
          success: false,
          error: 'User not found',
        })
      }

      const user = userResult.rows[0]

      // Проверяем текущий пароль
      const isPasswordValid = await CryptoService.verifyAuthToken(
        currentPassword,
        user.salt,
        user.auth_token
      )

      if (!isPasswordValid) {
        return reply.code(401).send({
          success: false,
          error: 'Current password is incorrect',
        })
      }

      // Генерируем новые ключи с новым паролем
      const keys = await CryptoService.generateUserKeys(newPassword, user.email)

      // Обновляем ТОЛЬКО salt и auth_token (encrypted_master_key остается без изменений!)
      await pool.query(
        `UPDATE users
         SET salt = $1, auth_token = $2
         WHERE username = $3`,
        [keys.salt, keys.authToken, username]
      )

      // Получаем ID сессий которые будут удалены (все КРОМЕ текущей)
      const sessionsToDelete = await pool.query(
        'SELECT id FROM sessions WHERE username = $1 AND jwt_token != $2',
        [username, currentToken]
      )

      // Удаляем все сессии КРОМЕ текущей
      await pool.query(
        'DELETE FROM sessions WHERE username = $1 AND jwt_token != $2',
        [username, currentToken]
      )

      // Уведомляем другие устройства о завершении сессий
      if (fastify.io) {
        sessionsToDelete.rows.forEach((session) => {
          fastify.io.to(username).emit('session:terminated', {
            sessionId: session.id,
            message: 'Your password has been changed from another device',
          })
        })

        // Уведомляем все устройства об обновлении списка сессий
        fastify.io.to(username).emit('sessions:updated')
      }

      return reply.code(200).send({
        success: true,
        message: 'Password changed successfully',
      })
    } catch (error) {
      console.error('❌ change-password error:', error)
      return reply.code(500).send({
        success: false,
        error: 'Internal server error',
      })
    }
  })

  // ===== DEVICE APPROVAL ENDPOINTS =====

  /**
   * POST /auth/approve-device
   * Approve new device login (called from primary device)
   */
  fastify.post<{
    Body: { pending_session_id: string }
  }>('/approve-device', { preHandler: authMiddleware }, async (request, reply) => {
    try {
      const { pending_session_id } = request.body
      const payload = request.user as JwtPayload

      if (!pending_session_id) {
        return reply.code(400).send({
          success: false,
          error: 'pending_session_id is required',
        })
      }

      // Проверяем что pending_session принадлежит этому пользователю
      const pendingSession = await pool.query(
        `SELECT * FROM pending_sessions
         WHERE id = $1 AND username = $2 AND status = 'pending' AND expires_at > NOW()`,
        [pending_session_id, payload.username]
      )

      if (pendingSession.rows.length === 0) {
        return reply.code(404).send({
          success: false,
          error: 'Pending session not found or expired',
        })
      }

      const session = pendingSession.rows[0]

      // Обновляем статус на 'approved'
      await pool.query(
        `UPDATE pending_sessions SET status = 'approved' WHERE id = $1`,
        [pending_session_id]
      )

      console.log('✅ Device approved, code:', session.approval_code)

      // Код отправляется ТОЛЬКО на primary device (в response)
      // Новое устройство НЕ получает код автоматически - пользователь вводит вручную
      return reply.send({
        success: true,
        data: {
          approval_code: session.approval_code,
          message: 'Device approved. Show this code to new device.',
        },
      })
    } catch (error) {
      console.error('❌ approve-device error:', error)
      return reply.code(500).send({
        success: false,
        error: 'Internal server error',
      })
    }
  })

  /**
   * POST /auth/reject-device
   * Reject new device login (called from primary device)
   */
  fastify.post<{
    Body: { pending_session_id: string }
  }>('/reject-device', { preHandler: authMiddleware }, async (request, reply) => {
    try {
      const { pending_session_id } = request.body
      const payload = request.user as JwtPayload

      if (!pending_session_id) {
        return reply.code(400).send({
          success: false,
          error: 'pending_session_id is required',
        })
      }

      // Проверяем что pending_session принадлежит этому пользователю
      const pendingSession = await pool.query(
        `SELECT * FROM pending_sessions
         WHERE id = $1 AND username = $2 AND status = 'pending' AND expires_at > NOW()`,
        [pending_session_id, payload.username]
      )

      if (pendingSession.rows.length === 0) {
        return reply.code(404).send({
          success: false,
          error: 'Pending session not found or expired',
        })
      }

      // Обновляем статус на 'rejected'
      await pool.query(
        `UPDATE pending_sessions SET status = 'rejected' WHERE id = $1`,
        [pending_session_id]
      )

      // Отправляем Socket.IO уведомление новому устройству
      fastify.io.to(pending_session_id).emit('device:rejected', {
        pending_session_id: pending_session_id,
        message: 'Device login rejected by primary device',
      })

      console.log('❌ Device rejected:', pending_session_id)

      return reply.send({
        success: true,
        message: 'Device login rejected',
      })
    } catch (error) {
      console.error('❌ reject-device error:', error)
      return reply.code(500).send({
        success: false,
        error: 'Internal server error',
      })
    }
  })

  /**
   * POST /auth/verify-device-code
   * Verify approval code and create session (called from new device)
   */
  fastify.post<{
    Body: { pending_session_id: string; code: string }
  }>('/verify-device-code', async (request, reply) => {
    try {
      const { pending_session_id, code } = request.body

      if (!pending_session_id || !code) {
        return reply.code(400).send({
          success: false,
          error: 'pending_session_id and code are required',
        })
      }

      // Проверяем pending_session
      const pendingSession = await pool.query(
        `SELECT * FROM pending_sessions
         WHERE id = $1 AND status = 'approved' AND expires_at > NOW()`,
        [pending_session_id]
      )

      if (pendingSession.rows.length === 0) {
        return reply.code(404).send({
          success: false,
          error: 'Pending session not found, not approved, or expired',
        })
      }

      const session = pendingSession.rows[0]

      // Проверяем код
      if (session.approval_code !== code) {
        return reply.code(401).send({
          success: false,
          error: 'Invalid approval code',
        })
      }

      // Код верный! Создаем полноценную сессию
      const username = session.username

      // Получаем user data
      const userResult = await pool.query('SELECT * FROM users WHERE username = $1', [username])
      const user = userResult.rows[0]

      // Генерируем JWT
      const token = JwtService.generate({
        username: user.username,
        email: user.email,
      })

      // Создаем сессию
      await pool.query(
        `INSERT INTO sessions (username, device_info, ip_address, jwt_token, device_fingerprint, is_primary, created_at, last_active, expires_at)
         VALUES ($1, $2, $3, $4, $5, false, NOW(), NOW(), NOW() + INTERVAL '30 days')`,
        [username, session.device_info, session.ip_address, token, session.device_fingerprint]
      )

      // Удаляем pending_session
      await pool.query('DELETE FROM pending_sessions WHERE id = $1', [pending_session_id])

      console.log('✅ Device verified and session created for:', username)

      return reply.send({
        success: true,
        data: {
          token,
          user: {
            username: user.username,
            email: user.email,
            email_verified: user.email_verified,
          },
        },
      })
    } catch (error) {
      console.error('❌ verify-device-code error:', error)
      return reply.code(500).send({
        success: false,
        error: 'Internal server error',
      })
    }
  })
}