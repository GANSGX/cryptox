import {
  encryptMessage,
  decryptMessage,
  deriveSessionKey,
} from "@/utils/crypto";
// import { signalService } from "./signal.service"; // DISABLED: не работает в браузере

class CryptoService {
  private sessionKeys: Map<string, string> = new Map();
  // private useSignalProtocol: boolean = false; // Feature flag - disabled

  /**
   * Получение или создание session key для чата
   */
  async getSessionKey(
    chatId: string,
    username1: string,
    username2: string,
  ): Promise<string> {
    let key = this.sessionKeys.get(chatId);

    if (!key) {
      // Проверяем localStorage
      const savedKey = localStorage.getItem(`session_key_${chatId}`);
      if (savedKey) {
        key = savedKey;
        this.sessionKeys.set(chatId, key);
      } else {
        // Генерируем детерминированный ключ из usernames
        key = await deriveSessionKey(username1, username2);
        this.sessionKeys.set(chatId, key);
        // Сохраняем в localStorage для персистентности
        localStorage.setItem(`session_key_${chatId}`, key);
      }
    }

    return key;
  }

  /**
   * Загрузка session keys из localStorage
   */
  loadSessionKeys() {
    const keys = Object.keys(localStorage);
    keys.forEach((key) => {
      if (key.startsWith("session_key_")) {
        const chatId = key.replace("session_key_", "");
        const sessionKey = localStorage.getItem(key);
        if (sessionKey) {
          this.sessionKeys.set(chatId, sessionKey);
        }
      }
    });
  }

  /**
   * Создание chat_id (как на сервере)
   */
  createChatId(username1: string, username2: string): string {
    const sorted = [username1.toLowerCase(), username2.toLowerCase()].sort();
    return `${sorted[0]}_${sorted[1]}`;
  }

  /**
   * Инициализация Signal Protocol (вызывать при логине)
   */
  async initializeSignal(username: string): Promise<void> {
    // TODO: Signal Protocol не работает в браузере (native библиотека)
    // Нужно либо:
    // 1. Найти браузерную альтернативу
    // 2. Реализовать самому X3DH + Double Ratchet
    // 3. Использовать WebAssembly версию

    // this.useSignalProtocol = false; // disabled
    void username; // Используется в будущем для Signal Protocol
    console.log("⚠️ Signal Protocol disabled (using fallback)");
  }

  /**
   * Шифрование сообщения для отправки
   */
  async encryptMessageForChat(
    message: string,
    otherUsername: string,
    myUsername: string,
  ): Promise<string> {
    // Signal Protocol отключен (не работает в браузере)
    // if (this.useSignalProtocol) { ... }

    // Используем детерминированный ключ (одинаковый у обоих юзеров)
    const chatId = this.createChatId(myUsername, otherUsername);
    const sessionKey = await this.getSessionKey(
      chatId,
      myUsername,
      otherUsername,
    );

    const { ciphertext, nonce } = encryptMessage(message, sessionKey);

    // Объединяем ciphertext и nonce (разделитель: :)
    return `${ciphertext}:${nonce}`;
  }

  /**
   * Расшифровка полученного сообщения
   */
  async decryptMessageFromChat(
    encryptedContent: string,
    otherUsername: string,
    myUsername: string,
  ): Promise<string | null> {
    // Signal Protocol отключен (не работает в браузере)
    // if (this.useSignalProtocol) { ... }

    // Используем детерминированный ключ (одинаковый у обоих юзеров)
    try {
      const chatId = this.createChatId(myUsername, otherUsername);
      const sessionKey = await this.getSessionKey(
        chatId,
        myUsername,
        otherUsername,
      );

      // Разделяем ciphertext и nonce
      const [ciphertext, nonce] = encryptedContent.split(":");

      if (!ciphertext || !nonce) {
        console.error("Invalid encrypted content format");
        return null;
      }

      return decryptMessage(ciphertext, nonce, sessionKey);
    } catch (err) {
      console.error("Decryption error:", err);
      return null;
    }
  }

  /**
   * Очистка session keys (при выходе)
   */
  clearSessionKeys() {
    this.sessionKeys.clear();
    const keys = Object.keys(localStorage);
    keys.forEach((key) => {
      if (key.startsWith("session_key_")) {
        localStorage.removeItem(key);
      }
    });
  }
}

export const cryptoService = new CryptoService();
