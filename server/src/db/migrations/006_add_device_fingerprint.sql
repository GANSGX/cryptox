-- Миграция: Добавление device fingerprint для надежной идентификации устройств
-- Описание: Добавляет поле device_fingerprint для определения "того же самого устройства"

-- Добавляем поле device_fingerprint к таблице sessions
ALTER TABLE sessions ADD COLUMN device_fingerprint VARCHAR(255);

-- Создаем индекс для быстрого поиска сессий по fingerprint
CREATE INDEX idx_sessions_fingerprint ON sessions(username, device_fingerprint);

-- Добавляем комментарий к колонке
COMMENT ON COLUMN sessions.device_fingerprint IS 'Уникальный отпечаток браузера/устройства (FingerprintJS). Используется для определения повторных логинов с того же устройства.';
