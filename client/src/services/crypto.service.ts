import { encryptMessage, decryptMessage, generateSessionKey } from '@/utils/crypto'

class CryptoService {
  private sessionKeys: Map<string, string> = new Map()

  /**
   * Получение или создание session key для чата
   */
  getSessionKey(chatId: string): string {
    let key = this.sessionKeys.get(chatId)

    if (!key) {
      key = generateSessionKey()
      this.sessionKeys.set(chatId, key)
      // Сохраняем в localStorage для персистентности
      localStorage.setItem(`session_key_${chatId}`, key)
    }

    return key
  }

  /**
   * Загрузка session keys из localStorage
   */
  loadSessionKeys() {
    const keys = Object.keys(localStorage)
    keys.forEach((key) => {
      if (key.startsWith('session_key_')) {
        const chatId = key.replace('session_key_', '')
        const sessionKey = localStorage.getItem(key)
        if (sessionKey) {
          this.sessionKeys.set(chatId, sessionKey)
        }
      }
    })
  }

  /**
   * Создание chat_id (как на сервере)
   */
  createChatId(username1: string, username2: string): string {
    const sorted = [username1.toLowerCase(), username2.toLowerCase()].sort()
    return `${sorted[0]}_${sorted[1]}`
  }

  /**
   * Шифрование сообщения для отправки
   */
  encryptMessageForChat(message: string, otherUsername: string, myUsername: string): string {
    const chatId = this.createChatId(myUsername, otherUsername)
    const sessionKey = this.getSessionKey(chatId)

    const { ciphertext, nonce } = encryptMessage(message, sessionKey)

    // Объединяем ciphertext и nonce (разделитель: :)
    return `${ciphertext}:${nonce}`
  }

  /**
   * Расшифровка полученного сообщения
   */
  decryptMessageFromChat(
    encryptedContent: string,
    otherUsername: string,
    myUsername: string
  ): string | null {
    try {
      const chatId = this.createChatId(myUsername, otherUsername)
      const sessionKey = this.getSessionKey(chatId)

      // Разделяем ciphertext и nonce
      const [ciphertext, nonce] = encryptedContent.split(':')

      if (!ciphertext || !nonce) {
        console.error('Invalid encrypted content format')
        return null
      }

      return decryptMessage(ciphertext, nonce, sessionKey)
    } catch (error) {
      console.error('Decryption error:', error)
      return null
    }
  }

  /**
   * Очистка session keys (при выходе)
   */
  clearSessionKeys() {
    this.sessionKeys.clear()
    const keys = Object.keys(localStorage)
    keys.forEach((key) => {
      if (key.startsWith('session_key_')) {
        localStorage.removeItem(key)
      }
    })
  }
}

export const cryptoService = new CryptoService()