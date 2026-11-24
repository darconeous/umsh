-- v29, as the Swift store applied it.
--
-- A reply whose Regarding could not be read, and a message
-- that came as an edit of something unknown: each says so.

ALTER TABLE chat_message
    ADD COLUMN regarding_unknown INTEGER NOT NULL DEFAULT 0;
ALTER TABLE chat_message
    ADD COLUMN unknown_original INTEGER NOT NULL DEFAULT 0;
