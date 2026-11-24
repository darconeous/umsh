-- v9, as the Swift store applied it.
--
-- Ordered-repair transcript metadata: `presence` marks a row as
-- a real message (0), a reserved gap placeholder (1), or a
-- permanent loss marker (2); `received_late` flags a backfill
-- that filled its slot out of order.

ALTER TABLE chat_message ADD COLUMN presence INTEGER NOT NULL DEFAULT 0;
ALTER TABLE chat_message ADD COLUMN received_late INTEGER NOT NULL DEFAULT 0;
