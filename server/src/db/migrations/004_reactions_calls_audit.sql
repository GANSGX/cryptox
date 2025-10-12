-- ========================================
-- Migration 004: Reactions, Calls, Audit
-- ========================================

-- ========================================
-- TABLE: reactions
-- ========================================
CREATE TABLE reactions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  
  message_id UUID REFERENCES messages(id) ON DELETE CASCADE,
  group_message_id UUID REFERENCES group_messages(id) ON DELETE CASCADE,
  
  username VARCHAR(30) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  
  emoji VARCHAR(10) NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  
  CONSTRAINT one_message_type CHECK (
    (message_id IS NOT NULL AND group_message_id IS NULL) OR
    (message_id IS NULL AND group_message_id IS NOT NULL)
  ),
  
  UNIQUE (message_id, username, emoji),
  UNIQUE (group_message_id, username, emoji)
);

CREATE INDEX idx_reactions_message ON reactions(message_id);
CREATE INDEX idx_reactions_group_message ON reactions(group_message_id);
CREATE INDEX idx_reactions_user ON reactions(username);

-- ========================================
-- TABLE: pinned_messages
-- ========================================
CREATE TABLE pinned_messages (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  
  chat_id VARCHAR(61),
  group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
  
  message_id UUID REFERENCES messages(id) ON DELETE CASCADE,
  group_message_id UUID REFERENCES group_messages(id) ON DELETE CASCADE,
  
  pinned_by VARCHAR(30) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  pinned_at TIMESTAMP DEFAULT NOW(),
  
  CONSTRAINT one_chat_type CHECK (
    (chat_id IS NOT NULL AND group_id IS NULL) OR
    (chat_id IS NULL AND group_id IS NOT NULL)
  ),
  
  CONSTRAINT one_message_type CHECK (
    (message_id IS NOT NULL AND group_message_id IS NULL) OR
    (message_id IS NULL AND group_message_id IS NOT NULL)
  )
);

CREATE INDEX idx_pinned_chat ON pinned_messages(chat_id);
CREATE INDEX idx_pinned_group ON pinned_messages(group_id);

-- ========================================
-- TABLE: calls
-- ========================================
CREATE TABLE calls (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  
  caller_username VARCHAR(30) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  callee_username VARCHAR(30) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  
  call_type VARCHAR(10) NOT NULL,
  status VARCHAR(20) NOT NULL,
  
  started_at TIMESTAMP DEFAULT NOW(),
  ended_at TIMESTAMP,
  duration INTEGER,
  
  CONSTRAINT call_type_check CHECK (call_type IN ('audio', 'video')),
  CONSTRAINT status_check CHECK (status IN ('initiated', 'ringing', 'answered', 'rejected', 'missed', 'ended', 'failed'))
);

CREATE INDEX idx_calls_caller ON calls(caller_username, started_at DESC);
CREATE INDEX idx_calls_callee ON calls(callee_username, started_at DESC);

-- ========================================
-- TABLE: push_subscriptions
-- ========================================
CREATE TABLE push_subscriptions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  
  username VARCHAR(30) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  
  endpoint TEXT NOT NULL UNIQUE,
  keys JSONB NOT NULL,
  user_agent TEXT,
  
  created_at TIMESTAMP DEFAULT NOW(),
  last_used TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_push_user ON push_subscriptions(username);

-- ========================================
-- TABLE: audit_log
-- ========================================
CREATE TABLE audit_log (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  
  username VARCHAR(30) REFERENCES users(username) ON DELETE SET NULL,
  
  action VARCHAR(100) NOT NULL,
  ip_address INET,
  
  details JSONB,
  
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_audit_user ON audit_log(username, created_at DESC);
CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_created ON audit_log(created_at DESC);

COMMENT ON TABLE reactions IS 'Реакции на сообщения (эмодзи)';
COMMENT ON TABLE pinned_messages IS 'Закреплённые сообщения (1-on-1 и группы)';
COMMENT ON TABLE calls IS 'История звонков (WebRTC)';
COMMENT ON TABLE push_subscriptions IS 'Web Push подписки (для браузерных уведомлений)';
COMMENT ON TABLE audit_log IS 'Журнал действий (безопасность и отладка)';