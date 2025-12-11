-- Add delivered_at field to messages table for delivery status tracking
-- This enables Telegram-like message status indicators:
-- 1 gray checkmark = sent (created_at set, delivered_at = null)
-- 2 gray checkmarks = delivered (delivered_at set, read_at = null)
-- 2 blue checkmarks = read (read_at set)

ALTER TABLE messages
ADD COLUMN delivered_at TIMESTAMP;

-- Add index for efficient queries on delivery status
CREATE INDEX idx_messages_delivery_status ON messages(sender_username, delivered_at) WHERE delivered_at IS NULL;

COMMENT ON COLUMN messages.delivered_at IS 'Timestamp when message was delivered to recipient (received via WebSocket)';
