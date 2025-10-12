-- ========================================
-- Migration 003: Groups
-- ========================================

-- ========================================
-- TABLE: groups
-- ========================================
CREATE TABLE groups (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  
  name VARCHAR(100) NOT NULL,
  description VARCHAR(500),
  avatar_path VARCHAR(500),
  
  owner_username VARCHAR(30) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  
  member_count INTEGER DEFAULT 1,
  max_members INTEGER DEFAULT 1000,
  
  -- Настройки группы (JSONB для гибкости)
  settings JSONB DEFAULT '{
    "who_can_add_members": "all",
    "who_can_send_messages": "all",
    "history_for_new_members": "visible"
  }'::jsonb
);

CREATE INDEX idx_groups_owner ON groups(owner_username);
CREATE INDEX idx_groups_created ON groups(created_at DESC);

-- ========================================
-- TABLE: group_members
-- ========================================
CREATE TABLE group_members (
  group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  username VARCHAR(30) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  
  role VARCHAR(20) DEFAULT 'member',
  
  -- Права для админов (JSONB для гибкости)
  permissions JSONB DEFAULT '{
    "can_delete_messages": false,
    "can_kick_members": false,
    "can_mute_members": false,
    "can_edit_group_info": false,
    "can_pin_messages": false,
    "can_add_members": false
  }'::jsonb,
  
  joined_at TIMESTAMP DEFAULT NOW(),
  muted_until TIMESTAMP,
  
  PRIMARY KEY (group_id, username),
  
  CONSTRAINT role_check CHECK (role IN ('owner', 'admin', 'member'))
);

CREATE INDEX idx_group_members_user ON group_members(username);
CREATE INDEX idx_group_members_role ON group_members(group_id, role);

-- ========================================
-- TABLE: group_messages
-- ========================================
CREATE TABLE group_messages (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  
  group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  sender_username VARCHAR(30) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  
  -- Зашифрованный контент (server-side, не E2E!)
  encrypted_content TEXT NOT NULL,
  
  message_type VARCHAR(20) DEFAULT 'text',
  media_id UUID REFERENCES media_files(id) ON DELETE SET NULL,
  
  reply_to_message_id UUID REFERENCES group_messages(id) ON DELETE SET NULL,
  
  created_at TIMESTAMP DEFAULT NOW(),
  edited_at TIMESTAMP,
  deleted_at TIMESTAMP,
  
  CONSTRAINT message_type_check CHECK (message_type IN ('text', 'image', 'video', 'file', 'audio', 'system'))
);

CREATE INDEX idx_group_messages_group ON group_messages(group_id, created_at DESC);
CREATE INDEX idx_group_messages_sender ON group_messages(sender_username);

-- Full-text search
CREATE INDEX idx_group_messages_search ON group_messages USING gin(to_tsvector('simple', encrypted_content));

-- ========================================
-- TABLE: group_invites
-- ========================================
CREATE TABLE group_invites (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  
  group_id UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  token UUID NOT NULL UNIQUE DEFAULT uuid_generate_v4(),
  
  created_by VARCHAR(30) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  
  created_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP,
  
  max_uses INTEGER,
  current_uses INTEGER DEFAULT 0,
  
  require_approval BOOLEAN DEFAULT FALSE,
  revoked BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_group_invites_token ON group_invites(token) WHERE revoked = FALSE;
CREATE INDEX idx_group_invites_group ON group_invites(group_id);

COMMENT ON TABLE groups IS 'Групповые чаты';
COMMENT ON TABLE group_members IS 'Участники групп (роли и права)';
COMMENT ON TABLE group_messages IS 'Сообщения в группах (server-side шифрование)';
COMMENT ON TABLE group_invites IS 'Пригласительные ссылки для групп';