import {
  generateSalt,
  generateMasterKey,
  generateVerificationCode,
  hashPassword,
  generateAuthToken,
  generateEmailRecoveryKey,
  deriveStorageKey,
  encrypt,
  decrypt,
} from '../utils/crypto.js'
import { env } from '../config/env.js'

/**
 * Сервис для криптографических операций
 */
export class CryptoService {
  private static readonly SERVER_SECRET = env.JWT_SECRET // Используем JWT_SECRET как server secret

  /**
   * Генерация данных для регистрации пользователя
   */
  static async generateUserKeys(password: string, email: string) {
    // 1. Генерация соли
    const salt = generateSalt()

    // 2. Генерация Password Key (Argon2)
    const passwordKey = await hashPassword(password, salt)

    // 3. Генерация Auth Token
    const authToken = generateAuthToken(passwordKey)

    // 4. Генерация Master Key
    const masterKey = generateMasterKey()

    // 5. Генерация Email Recovery Key
    const emailRecoveryKey = await generateEmailRecoveryKey(email, this.SERVER_SECRET)

    // 6. Шифрование Master Key через Email Recovery Key
    const { ciphertext: encryptedMasterKey, nonce: masterKeyNonce } = encrypt(
      masterKey,
      emailRecoveryKey
    )

    // 7. Генерация Storage Key
    const storageKey = deriveStorageKey(masterKey)

    return {
      salt,
      authToken,
      encryptedMasterKey,
      masterKeyNonce,
      // Эти ключи НЕ отправляются на сервер (только для клиента)
      clientOnly: {
        masterKey,
        passwordKey,
        storageKey,
      },
    }
  }

  /**
   * Проверка Auth Token при логине
   */
  static async verifyAuthToken(password: string, salt: string, storedAuthToken: string): Promise<boolean> {
    const passwordKey = await hashPassword(password, salt)
    const authToken = generateAuthToken(passwordKey)
    return authToken === storedAuthToken
  }

  /**
   * Расшифровка Master Key (для восстановления на новом устройстве)
   */
  static async decryptMasterKey(
    encryptedMasterKey: string,
    masterKeyNonce: string,
    email: string
  ): Promise<string | null> {
    const emailRecoveryKey = await generateEmailRecoveryKey(email, this.SERVER_SECRET)
    return decrypt(encryptedMasterKey, masterKeyNonce, emailRecoveryKey)
  }

  /**
   * Генерация кода подтверждения email (6 цифр)
   */
  static generateEmailCode(): string {
    return generateVerificationCode()
  }

  /**
   * Шифрование данных (например, для истории на сервере)
   */
  static encryptData(data: string, key: string) {
    return encrypt(data, key)
  }

  /**
   * Расшифровка данных
   */
  static decryptData(ciphertext: string, nonce: string, key: string) {
    return decrypt(ciphertext, nonce, key)
  }
}