-- v10, as the Swift store applied it.
--
-- An outbound message that failed transport but was later
-- acknowledged via a resend is "Delivered Late".

ALTER TABLE chat_message ADD COLUMN delivered_late INTEGER NOT NULL DEFAULT 0;
