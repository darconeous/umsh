-- v5, as the Swift store applied it.

ALTER TABLE chat_message ADD COLUMN edited INTEGER NOT NULL DEFAULT 0;
