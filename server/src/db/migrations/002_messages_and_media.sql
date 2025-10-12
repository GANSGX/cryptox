-- ========================================
-- Migration 002: Messages and Media
-- ========================================

-- ========================================
-- TABLE: messages (1-on-1 чаты, E2E)
-- ========================================
CREATE TABLE messages (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  
  -- Chat ID (sorted usernames: alice_bob)
  chat_id VARCHAR(61) NOT NULL,
  
  sender_username VARCHAR(30) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  recipient_username VARCHAR(30) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  
  -- Зашифрованный контент (Signal Protocol)
  encrypted_content TEXT NOT NULL,
  
  message_type VARCHAR(20) DEFAULT 'text',
  media_id UUID,
  
  -- Reply/Forward
  reply_to_message_id UUID REFERENCES messages(id) ON DELETE SET NULL,
  forwarded_from VARCHAR(30) REFERENCES users(username) ON DELETE SET NULL,
  
  -- Timestamps
  created_at TIMESTAMP DEFAULT NOW(),
  edited_at TIMESTAMP,
  deleted_at TIMESTAMP,
  read_at TIMESTAMP,
  
  CONSTRAINT message_type_check CHECK (message_type IN ('text', 'image', 'video', 'file', 'audio'))
);

CREATE INDEX idx_messages_chat ON messages(chat_id, created_at DESC);
CREATE INDEX idx_messages_recipient ON messages(recipient_username, read_at) WHERE read_at IS NULL;
CREATE INDEX idx_messages_sender ON messages(sender_username);

-- Full-text search
CREATE INDEX idx_messages_search ON messages USING gin(to_tsvector('simple', encrypted_content));

-- ========================================
-- TABLE: media_files
-- ========================================
CREATE TABLE media_files (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  
  owner_username VARCHAR(30) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  
  file_type VARCHAR(20) NOT NULL,
  file_path VARCHAR(500) NOT NULL,
  file_name VARCHAR(255) NOT NULL,
  file_size BIGINT NOT NULL,
  mime_type VARCHAR(100),
  
  -- Зашифрованный ключ для расшифровки файла
  encrypted_key TEXT NOT NULL,
  
  -- Превью
  thumbnail_path VARCHAR(500),
  
  -- Метаданные
  width INTEGER,
  height INTEGER,
  duration INTEGER,
  
  uploaded_at TIMESTAMP DEFAULT NOW(),
  
  CONSTRAINT file_type_check CHECK (file_type IN ('image', 'video', 'file', 'audio'))
);

CREATE INDEX idx_media_owner ON media_files(owner_username);
CREATE INDEX idx_media_type ON media_files(file_type);

-- ========================================
-- TABLE: contacts
-- ========================================
CREATE TABLE contacts (
  username VARCHAR(30) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  contact_username VARCHAR(30) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  
  added_at TIMESTAMP DEFAULT NOW(),
  is_blocked BOOLEAN DEFAULT FALSE,
  
  PRIMARY KEY (username, contact_username)
);

CREATE INDEX idx_contacts_blocked ON contacts(username) WHERE is_blocked = TRUE;

-- ========================================
-- TABLE: pending_messages
-- ========================================
CREATE TABLE pending_messages (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  
  recipient_username VARCHAR(30) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  
  -- Сериализованные данные сообщения
  message_data JSONB NOT NULL,
  
  created_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_pending_recipient ON pending_messages(recipient_username, created_at);
CREATE INDEX idx_pending_expires ON pending_messages(expires_at);

COMMENT ON TABLE messages IS '1-on-1 сообщения (E2E зашифрованные)';
COMMENT ON TABLE media_files IS 'Метаданные медиа файлов';
COMMENT ON TABLE contacts IS 'Контакты и блокировки';
COMMENT ON TABLE pending_messages IS 'Сообщения для offline пользователей (TTL 3 дня)';