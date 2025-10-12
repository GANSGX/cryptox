-- ========================================
-- CRYPTOX DATABASE SCHEMA
-- Migration 001: Initial Schema
-- ========================================

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ========================================
-- TABLE: users
-- ========================================
CREATE TABLE users (
  username VARCHAR(30) PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  email_verified BOOLEAN DEFAULT FALSE,
  
  -- Криптография
  salt VARCHAR(255) NOT NULL,
  auth_token VARCHAR(255) NOT NULL,
  encrypted_master_key TEXT NOT NULL,
  public_key TEXT NOT NULL,
  data_version INTEGER DEFAULT 2,
  
  -- Профиль
  avatar_path VARCHAR(500),
  bio VARCHAR(200),
  
  -- Метаданные
  created_at TIMESTAMP DEFAULT NOW(),
  last_seen TIMESTAMP DEFAULT NOW(),
  
  -- Антиспам
  spam_score INTEGER DEFAULT 0,
  is_banned BOOLEAN DEFAULT FALSE,
  
  -- Индексы
  CONSTRAINT username_length CHECK (char_length(username) >= 3 AND char_length(username) <= 30),
  CONSTRAINT username_format CHECK (username ~ '^[a-z0-9_]+$')
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_last_seen ON users(last_seen);
CREATE INDEX idx_users_spam_score ON users(spam_score) WHERE spam_score > 0;

-- ========================================
-- TABLE: sessions
-- ========================================
CREATE TABLE sessions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  username VARCHAR(30) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  
  device_info JSONB,
  ip_address INET,
  jwt_token TEXT NOT NULL UNIQUE,
  
  created_at TIMESTAMP DEFAULT NOW(),
  last_active TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_sessions_username ON sessions(username);
CREATE INDEX idx_sessions_token ON sessions(jwt_token);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);

-- ========================================
-- TABLE: email_verifications
-- ========================================
CREATE TABLE email_verifications (
  username VARCHAR(30) PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
  code VARCHAR(6) NOT NULL,
  attempts INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_email_verifications_expires ON email_verifications(expires_at);

-- ========================================
-- TABLE: password_recovery
-- ========================================
CREATE TABLE password_recovery (
  token UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  username VARCHAR(30) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  used BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_password_recovery_username ON password_recovery(username);
CREATE INDEX idx_password_recovery_expires ON password_recovery(expires_at);

COMMENT ON TABLE users IS 'Пользователи мессенджера';
COMMENT ON TABLE sessions IS 'Активные сессии (multi-device)';
COMMENT ON TABLE email_verifications IS 'Коды подтверждения email';
COMMENT ON TABLE password_recovery IS 'Токены восстановления пароля';