-- v32: the first schema the Swift store does not share.

-- Nodes: no sort key, which nothing read, and instants in integer
-- milliseconds like every other column.
DROP INDEX node_owner_alias_search_idx;
ALTER TABLE node DROP COLUMN alias_search;

ALTER TABLE node ADD COLUMN last_heard_at_ms INTEGER;
ALTER TABLE node ADD COLUMN advertisement_received_at_ms INTEGER;
UPDATE node SET
    last_heard_at_ms = CAST(round(last_heard_at * 1000) AS INTEGER),
    advertisement_received_at_ms = CAST(round(advertisement_received_at * 1000) AS INTEGER);
DROP INDEX node_owner_transient_heard_idx;
ALTER TABLE node DROP COLUMN last_heard_at;
ALTER TABLE node DROP COLUMN advertisement_received_at;
CREATE INDEX node_owner_transient_heard_idx
    ON node (owner_identity_id, is_saved, last_heard_at_ms);

-- An absent blob is NULL, never empty, as this store writes one.
UPDATE chat_message SET background_color = NULL WHERE length(background_color) = 0;
UPDATE chat_message SET text_color = NULL WHERE length(text_color) = 0;
UPDATE chat_message SET sender_hint = NULL WHERE length(sender_hint) = 0;
UPDATE chat_message SET regarding_sender_hint = NULL
    WHERE length(regarding_sender_hint) = 0;
UPDATE chat_message SET rx_route_hints = NULL WHERE length(rx_route_hints) = 0;
UPDATE chat_delivery_fragment SET repeaters = NULL WHERE length(repeaters) = 0;
UPDATE node_peer_repeaters SET next_cursor = NULL WHERE length(next_cursor) = 0;
UPDATE node_peer_repeater_entry SET region_codes = NULL WHERE length(region_codes) = 0;
