import FingerprintJS from "@fingerprintjs/fingerprintjs";

/**
 * Сервис для генерации уникального отпечатка браузера
 * Использует FingerprintJS для максимально точной идентификации
 */
class FingerprintService {
  private fpPromise: ReturnType<typeof FingerprintJS.load> | null = null;

  /**
   * Инициализация FingerprintJS
   */
  private async initialize() {
    if (!this.fpPromise) {
      this.fpPromise = FingerprintJS.load();
    }
    return this.fpPromise;
  }

  /**
   * Получить fingerprint текущего браузера/устройства
   * Возвращает стабильный хеш, который НЕ меняется при:
   * - Перезагрузке браузера
   * - Очистке cookies
   * - Режиме инкогнито (частично)
   *
   * Основан на:
   * - Canvas fingerprinting
   * - WebGL fingerprinting
   * - Audio fingerprinting
   * - Screen resolution
   * - Timezone
   * - Fonts
   * - Hardware (CPU cores, memory)
   * - Plugins
   * - И еще ~20 параметров
   */
  async getFingerprint(): Promise<string> {
    try {
      const fp = await this.initialize();
      const result = await fp.get();

      // result.visitorId - это стабильный хеш (99.5% точность)
      return result.visitorId;
    } catch (err) {
      console.error("Failed to generate fingerprint:", err);

      // Fallback: генерируем простой fingerprint на основе доступных данных
      return this.getFallbackFingerprint();
    }
  }

  /**
   * Fallback fingerprint (если FingerprintJS не работает)
   * Менее надежный, но лучше чем ничего
   */
  private getFallbackFingerprint(): string {
    const data = {
      userAgent: navigator.userAgent,
      language: navigator.language,
      platform: navigator.platform,
      screenResolution: `${screen.width}x${screen.height}x${screen.colorDepth}`,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      hardwareConcurrency: navigator.hardwareConcurrency || 0,
      deviceMemory:
        (navigator as unknown as { deviceMemory?: number }).deviceMemory || 0,
    };

    // Простой хеш
    const str = JSON.stringify(data);
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash; // Convert to 32bit integer
    }

    return `fallback_${Math.abs(hash).toString(36)}`;
  }

  /**
   * Проверить, поддерживается ли fingerprinting в этом браузере
   */
  async isSupported(): Promise<boolean> {
    try {
      await this.initialize();
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Получить Browser Session ID
   * Уникален для каждой СЕССИИ браузера (закрыл окно/incognito → новый ID)
   * Используется для различения обычного окна и incognito
   *
   * Хранится в sessionStorage (очищается при закрытии окна/вкладки)
   */
  getBrowserSessionId(): string {
    const STORAGE_KEY = "cryptox_browser_session_id";

    // Проверяем есть ли уже в sessionStorage
    let sessionId = sessionStorage.getItem(STORAGE_KEY);

    if (!sessionId) {
      // Генерируем новый уникальный ID
      sessionId = `session_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`;
      sessionStorage.setItem(STORAGE_KEY, sessionId);
      console.log("🆕 Generated new browser session ID:", sessionId);
    } else {
      console.log("♻️  Using existing browser session ID:", sessionId);
    }

    return sessionId;
  }
}

export const fingerprintService = new FingerprintService();
