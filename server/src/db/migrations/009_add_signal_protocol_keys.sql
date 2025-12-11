-- Migration: 009 - Add Signal Protocol Key Storage
-- Created: 2025-12-11
-- Description: Добавление таблиц для хранения Signal Protocol ключей

-- Таблица для Identity Keys и Signed PreKeys
CREATE TABLE IF NOT EXISTS signal_identity_keys (
  username VARCHAR(30) PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
  registration_id INT NOT NULL,
  identity_key TEXT NOT NULL,
  signed_prekey_id INT NOT NULL,
  signed_prekey_public TEXT NOT NULL,
  signed_prekey_signature TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Таблица для One-Time PreKeys
CREATE TABLE IF NOT EXISTS signal_prekeys (
  id SERIAL PRIMARY KEY,
  username VARCHAR(30) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  key_id INT NOT NULL,
  public_key TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(username, key_id)
);

-- Индекс для быстрого поиска prekeys
CREATE INDEX IF NOT EXISTS idx_signal_prekeys_username ON signal_prekeys(username);

-- Комментарии
COMMENT ON TABLE signal_identity_keys IS 'Хранение Identity Keys и Signed PreKeys для Signal Protocol';
COMMENT ON TABLE signal_prekeys IS 'Хранение One-Time PreKeys для Signal Protocol';
COMMENT ON COLUMN signal_identity_keys.registration_id IS 'Registration ID пользователя';
COMMENT ON COLUMN signal_identity_keys.identity_key IS 'Public Identity Key (base64)';
COMMENT ON COLUMN signal_identity_keys.signed_prekey_id IS 'ID текущего Signed PreKey';
COMMENT ON COLUMN signal_identity_keys.signed_prekey_public IS 'Public Signed PreKey (base64)';
COMMENT ON COLUMN signal_identity_keys.signed_prekey_signature IS 'Signature Signed PreKey (base64)';
COMMENT ON COLUMN signal_prekeys.key_id IS 'ID One-Time PreKey';
COMMENT ON COLUMN signal_prekeys.public_key IS 'Public One-Time PreKey (base64)';
