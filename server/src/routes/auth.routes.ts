import type { FastifyInstance } from 'fastify'
import { UserService } from '../services/user.service.js'
import { CryptoService } from '../services/crypto.service.js'
import { JwtService } from '../services/jwt.service.js'
import {
  isValidUsername,
  isValidEmail,
  isValidPassword,
} from '../utils/crypto.js'
import type { RegisterRequest, RegisterResponse, ApiResponse } from '../types/api.types.js'

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
}