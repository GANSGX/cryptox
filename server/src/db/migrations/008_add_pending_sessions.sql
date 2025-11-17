-- Миграция: Таблица для ожидающих подтверждения сессий (Device Approval)
-- Описание: Новые устройства сначала попадают сюда, требуют подтверждения с primary device

CREATE TABLE IF NOT EXISTS pending_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username VARCHAR(30) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  device_fingerprint VARCHAR(255) NOT NULL,
  device_info JSONB,
  ip_address INET,
  approval_code VARCHAR(6) NOT NULL,
  status VARCHAR(20) DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP DEFAULT NOW() + INTERVAL '5 minutes',

  CHECK (status IN ('pending', 'approved', 'rejected'))
);

-- Индексы для быстрого поиска
CREATE INDEX idx_pending_sessions_username ON pending_sessions(username);
CREATE INDEX idx_pending_sessions_expires ON pending_sessions(expires_at);
CREATE INDEX idx_pending_sessions_status ON pending_sessions(status);

-- Комментарий
COMMENT ON TABLE pending_sessions IS 'Сессии ожидающие подтверждения с primary device (TTL 5 минут)';

-- Автоочистка истекших pending_sessions (через cron job или периодический запрос)
-- DELETE FROM pending_sessions WHERE expires_at < NOW();
