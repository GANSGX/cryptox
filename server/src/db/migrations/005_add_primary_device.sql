-- Миграция: Добавление концепции главного устройства
-- Описание: Первое устройство становится главным (primary) и его нельзя удалить с других устройств

-- Добавляем поле is_primary к таблице sessions
ALTER TABLE sessions ADD COLUMN is_primary BOOLEAN DEFAULT FALSE;

-- Создаем индекс для быстрого поиска главной сессии
CREATE INDEX idx_sessions_primary ON sessions(username, is_primary) WHERE is_primary = TRUE;

-- Для существующих пользователей: устанавливаем первую (самую старую) сессию как главную
UPDATE sessions s1
SET is_primary = TRUE
WHERE s1.id = (
  SELECT s2.id
  FROM sessions s2
  WHERE s2.username = s1.username
  ORDER BY s2.created_at ASC
  LIMIT 1
)
AND NOT EXISTS (
  SELECT 1 FROM sessions s3
  WHERE s3.username = s1.username AND s3.is_primary = TRUE
);

-- Добавляем комментарий к колонке
COMMENT ON COLUMN sessions.is_primary IS 'Главное устройство пользователя. Нельзя удалить с других устройств. Можно передать статус.';
