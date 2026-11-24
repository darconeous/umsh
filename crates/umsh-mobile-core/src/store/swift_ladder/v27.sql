-- v27, as the Swift store applied it.
--
-- The repeaters overheard carrying each frame: the two-byte
-- hints of those that named themselves, in the order first
-- heard, and a count of those that did not. A message keeps
-- when its delivery last moved, so the transcript can tell a
-- send still collecting repeats from one gone quiet.

ALTER TABLE chat_delivery_fragment ADD COLUMN repeaters BLOB;
ALTER TABLE chat_delivery_fragment
    ADD COLUMN anonymous_repeats INTEGER NOT NULL DEFAULT 0;
ALTER TABLE chat_message ADD COLUMN delivery_progress_at_ms INTEGER;
