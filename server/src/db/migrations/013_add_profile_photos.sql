-- 013: Add profile photos table (Telegram-style photo gallery)
-- Allows users to upload multiple profile photos and switch between them

CREATE TABLE IF NOT EXISTS profile_photos (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username VARCHAR(50) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  photo_path TEXT NOT NULL,
  is_primary BOOLEAN DEFAULT false,
  position INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

  -- Constraints
  CONSTRAINT fk_username FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

-- Index for quick lookup by username
CREATE INDEX idx_profile_photos_username ON profile_photos(username);

-- Index for ordering photos
CREATE INDEX idx_profile_photos_position ON profile_photos(username, position);

-- Only one primary photo per user
CREATE UNIQUE INDEX idx_one_primary_per_user ON profile_photos(username, is_primary) WHERE is_primary = true;
