-- v28, as the Swift store applied it.
--
-- A test message on EMERGENCY that arrived while no one
-- asked to hear of them: kept and shown, never unread.

ALTER TABLE chat_message ADD COLUMN silent INTEGER NOT NULL DEFAULT 0;
