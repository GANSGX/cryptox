-- Миграция: Таблица для постоянного хранения информации о главных устройствах
-- Описание: Даже если сессия истекла/удалена, информация о том что устройство было primary сохраняется

-- Создаем таблицу primary_devices
CREATE TABLE IF NOT EXISTS primary_devices (
  username VARCHAR(30) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  device_fingerprint VARCHAR(255) NOT NULL,
  first_seen TIMESTAMP DEFAULT NOW(),
  last_seen TIMESTAMP DEFAULT NOW(),

  PRIMARY KEY (username, device_fingerprint)
);

-- Создаем индекс для быстрого поиска
CREATE INDEX idx_primary_devices_fingerprint ON primary_devices(device_fingerprint);

-- Добавляем комментарий
COMMENT ON TABLE primary_devices IS 'Постоянный список главных устройств пользователей (даже после истечения сессий)';

-- Заполняем таблицу существующими primary устройствами
INSERT INTO primary_devices (username, device_fingerprint, first_seen, last_seen)
SELECT
  username,
  device_fingerprint,
  created_at,
  last_active
FROM sessions
WHERE is_primary = TRUE AND device_fingerprint IS NOT NULL
ON CONFLICT (username, device_fingerprint) DO NOTHING;
