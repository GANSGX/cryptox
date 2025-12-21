-- Применение миграции 013: Галерея фотографий профиля
-- Запусти через: psql -U postgres -d cryptox -f apply_migration_013.sql

CREATE TABLE IF NOT EXISTS profile_photos (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username VARCHAR(50) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  photo_path TEXT NOT NULL,
  is_primary BOOLEAN DEFAULT false,
  position INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_profile_photos_username ON profile_photos(username);
CREATE INDEX IF NOT EXISTS idx_profile_photos_position ON profile_photos(username, position);
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_primary_per_user ON profile_photos(username, is_primary) WHERE is_primary = true;

INSERT INTO migrations (name) VALUES ('013_add_profile_photos.sql') ON CONFLICT (name) DO NOTHING;
