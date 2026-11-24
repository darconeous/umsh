-- v30, as the Swift store applied it.
--
-- Whether a message of mine went under a session with forward
-- secrecy. Null where nothing says: inbound, and older rows.

ALTER TABLE chat_message ADD COLUMN forward_secret INTEGER;
