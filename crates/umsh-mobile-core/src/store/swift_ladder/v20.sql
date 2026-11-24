-- v20, as the Swift store applied it.
--
-- Which transmission a message row reports delivery for. A
-- row's primary key is its compose identity and never moves—
-- edits and reactions reference it—but the transmission
-- carrying its content changes whenever an edit (or a resend,
-- which airs as one) supersedes the original frames under the
-- edit's own engine handle. These columns are the pointer the
-- delivery-evidence machinery follows; they start equal to
-- the row's own key and are re-aimed at each edit.
--
-- Backfilled for every existing row rather than outbound only:
-- handles are unique within a facade session regardless of
-- direction, so an inbound row can never match outbound
-- evidence, and one uniform rule beats a nullable special case.

ALTER TABLE chat_message ADD COLUMN delivery_session_id TEXT;
ALTER TABLE chat_message ADD COLUMN delivery_handle INTEGER;

UPDATE chat_message
SET delivery_session_id = session_id, delivery_handle = handle;

CREATE INDEX chat_message_delivery_idx ON chat_message (
    owner_identity_id, delivery_session_id, delivery_handle
);
