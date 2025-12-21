-- ========================================
-- CRYPTOX DATABASE SCHEMA
-- Migration 012: Add Profile Fields
-- ========================================

-- Добавляем поля для профиля пользователя
ALTER TABLE users ADD COLUMN IF NOT EXISTS birthday DATE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS status VARCHAR(70);

-- Настройки приватности
ALTER TABLE users ADD COLUMN IF NOT EXISTS status_privacy VARCHAR(20) DEFAULT 'everyone';
ALTER TABLE users ADD COLUMN IF NOT EXISTS online_privacy VARCHAR(20) DEFAULT 'everyone';
ALTER TABLE users ADD COLUMN IF NOT EXISTS typing_privacy VARCHAR(20) DEFAULT 'everyone';

-- Проверка валидности значений приватности
ALTER TABLE users ADD CONSTRAINT check_status_privacy
  CHECK (status_privacy IN ('everyone', 'chats', 'friends', 'nobody'));

ALTER TABLE users ADD CONSTRAINT check_online_privacy
  CHECK (online_privacy IN ('everyone', 'chats', 'friends', 'nobody'));

ALTER TABLE users ADD CONSTRAINT check_typing_privacy
  CHECK (typing_privacy IN ('everyone', 'chats', 'friends', 'nobody'));

COMMENT ON COLUMN users.birthday IS 'День рождения пользователя';
COMMENT ON COLUMN users.status IS 'Статус пользователя (до 70 символов)';
COMMENT ON COLUMN users.status_privacy IS 'Кто может видеть мой статус';
COMMENT ON COLUMN users.online_privacy IS 'Кто может видеть когда я онлайн';
COMMENT ON COLUMN users.typing_privacy IS 'Кто может видеть индикаторы печати';
