import argon2 from 'argon2'
import nacl from 'tweetnacl'
import { randomBytes, createHmac, createHash } from 'crypto'

// Добавляем hexToBytes вручную
function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex string')
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16)
  }
  return bytes
}

// bytesToHex вручную
function bytesToHex(bytes: Uint8Array | Buffer): string {
  return Buffer.from(bytes).toString('hex')
}

// ========================================
// Генерация случайных данных
// ========================================

/**
 * Генерация случайного salt для пароля
 */
export function generateSalt(): string {
  return bytesToHex(randomBytes(32))
}

/**
 * Генерация Master Key (32 байта)
 */
export function generateMasterKey(): string {
  return bytesToHex(randomBytes(32))
}

/**
 * Генерация случайного кода (6 цифр для email)
 */
export function generateVerificationCode(): string {
  return Math.floor(100000 + Math.random() * 900000).toString()
}

// ========================================
// Argon2 хэширование
// ========================================

/**
 * Генерация Password Key из пароля
 * Используется на клиенте, но нужно для тестов
 */
export async function hashPassword(password: string, salt: string): Promise<string> {
  const saltBuffer = Buffer.from(hexToBytes(salt))
  
  const hash = await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536, // 64 MB
    timeCost: 3,       // 3 итерации
    parallelism: 2,
    salt: saltBuffer,
    hashLength: 32,
    raw: true,
  })
  
  return bytesToHex(new Uint8Array(hash))
}

/**
 * Генерация Auth Token из Password Key
 */
export function generateAuthToken(passwordKey: string): string {
  const keyBuffer = Buffer.from(hexToBytes(passwordKey))
  const hmac = createHmac('sha256', keyBuffer)
  hmac.update('auth')
  return hmac.digest('hex')
}

/**
 * Генерация Email Recovery Key
 */
export async function generateEmailRecoveryKey(email: string, serverSecret: string): Promise<string> {
  const combined = email.toLowerCase() + serverSecret
  const hash = createHash('sha256')
  hash.update(combined, 'utf-8')
  return hash.digest('hex')
}

/**
 * Генерация Storage Key из Master Key
 */
export function deriveStorageKey(masterKey: string): string {
  const keyBuffer = Buffer.from(hexToBytes(masterKey))
  const hmac = createHmac('sha256', keyBuffer)
  hmac.update('storage')
  return hmac.digest('hex')
}

// ========================================
// Шифрование/Расшифровка (AES-256-GCM симуляция через NaCl)
// ========================================

/**
 * Шифрование данных (symmetric)
 */
export function encrypt(data: string, key: string): { ciphertext: string; nonce: string } {
  const keyBytes = hexToBytes(key).slice(0, 32)
  const nonce = randomBytes(24)
  const dataBytes = Buffer.from(data, 'utf-8')
  
  const ciphertext = nacl.secretbox(dataBytes, nonce, keyBytes)
  
  return {
    ciphertext: bytesToHex(ciphertext),
    nonce: bytesToHex(nonce),
  }
}

/**
 * Расшифровка данных
 */
export function decrypt(ciphertext: string, nonce: string, key: string): string | null {
  const keyBytes = hexToBytes(key).slice(0, 32)
  const nonceBytes = hexToBytes(nonce)
  const ciphertextBytes = hexToBytes(ciphertext)
  
  const decrypted = nacl.secretbox.open(ciphertextBytes, nonceBytes, keyBytes)
  
  if (!decrypted) {
    return null
  }
  
  return Buffer.from(decrypted).toString('utf-8')
}

// ========================================
// Валидация
// ========================================

/**
 * Валидация username
 */
export function isValidUsername(username: string): boolean {
  const regex = /^[a-z0-9_]{3,30}$/
  return regex.test(username)
}

/**
 * Валидация email
 */
export function isValidEmail(email: string): boolean {
  const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return regex.test(email)
}

/**
 * Валидация password
 */
export function isValidPassword(password: string): boolean {
  return password.length >= 8
}