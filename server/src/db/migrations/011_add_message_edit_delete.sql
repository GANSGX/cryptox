-- ================================================
-- Migration: Add message edit and delete support
-- ================================================
-- Adds fields for editing and deleting messages
-- - edited_at: timestamp when message was edited
-- - deleted_for_sender: soft delete for sender
-- - deleted_for_recipient: soft delete for recipient
-- ================================================

-- Add edited_at column
ALTER TABLE messages
ADD COLUMN edited_at TIMESTAMP DEFAULT NULL;

COMMENT ON COLUMN messages.edited_at IS 'Timestamp when message was last edited (NULL if never edited)';

-- Add deletion flags (soft delete approach)
ALTER TABLE messages
ADD COLUMN deleted_for_sender BOOLEAN DEFAULT FALSE,
ADD COLUMN deleted_for_recipient BOOLEAN DEFAULT FALSE;

COMMENT ON COLUMN messages.deleted_for_sender IS 'Message deleted by sender (hide from sender only)';
COMMENT ON COLUMN messages.deleted_for_recipient IS 'Message deleted by recipient (hide from recipient only)';

-- Create index for efficient filtering of non-deleted messages
CREATE INDEX idx_messages_deleted_status ON messages(sender_username, recipient_username, deleted_for_sender, deleted_for_recipient);

-- Create index for checking edit eligibility (30 min window)
CREATE INDEX idx_messages_created_at ON messages(created_at);

COMMENT ON INDEX idx_messages_deleted_status IS 'Optimize queries filtering by deletion status';
COMMENT ON INDEX idx_messages_created_at IS 'Optimize edit time window checks (30 minutes from created_at)';
