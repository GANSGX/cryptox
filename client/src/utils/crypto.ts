import nacl from 'tweetnacl'

// Utility functions для работы с Base64 и UTF8
function encodeBase64(arr: Uint8Array): string {
  return btoa(String.fromCharCode.apply(null, Array.from(arr)))
}

function decodeBase64(str: string): Uint8Array {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0))
}

function encodeUTF8(str: string): Uint8Array {
  return new TextEncoder().encode(str)
}

function decodeUTF8(arr: Uint8Array): string {
  return new TextDecoder().decode(arr)
}

/**
 * Генерация случайного ключа (32 байта)
 */
export function generateKey(): string {
  const key = nacl.randomBytes(32)
  return encodeBase64(key)
}

/**
 * Генерация session key для чата
 */
export function generateSessionKey(): string {
  return generateKey()
}

/**
 * Шифрование сообщения
 */
export function encryptMessage(message: string, key: string): { ciphertext: string; nonce: string } {
  const keyUint8 = decodeBase64(key)
  const nonce = nacl.randomBytes(24)
  const messageUint8 = encodeUTF8(message)
  
  const encrypted = nacl.secretbox(messageUint8, nonce, keyUint8)
  
  return {
    ciphertext: encodeBase64(encrypted),
    nonce: encodeBase64(nonce),
  }
}

/**
 * Расшифровка сообщения
 */
export function decryptMessage(ciphertext: string, nonce: string, key: string): string | null {
  try {
    const keyUint8 = decodeBase64(key)
    const nonceUint8 = decodeBase64(nonce)
    const ciphertextUint8 = decodeBase64(ciphertext)
    
    const decrypted = nacl.secretbox.open(ciphertextUint8, nonceUint8, keyUint8)
    
    if (!decrypted) {
      return null
    }
    
    return decodeUTF8(decrypted)
  } catch (error) {
    console.error('Decryption error:', error)
    return null
  }
}

/**
 * Генерация salt (для будущего)
 */
export function generateSalt(): string {
  const salt = nacl.randomBytes(32)
  return encodeBase64(salt)
}

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