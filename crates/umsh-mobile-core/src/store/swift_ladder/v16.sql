-- v16, as the Swift store applied it.
--
-- Chat is no longer only between two peers, so the column that
-- identified a transcript's other end is renamed to what it
-- actually holds: a conversation address, which is a peer's
-- address for a direct chat and a channel tag for a group.
-- The facade emits exactly this string, so the rename keeps
-- one vocabulary from the engine to the table.
--
-- Channel messages also carry what a multicast frame carries
-- and a unicast does not—a claimed sender hint—plus the
-- radio metadata of the frame each message arrived on, which
-- the transcript can now show per message.

ALTER TABLE chat_message RENAME COLUMN peer_address TO conversation_address;
ALTER TABLE chat_stream_checkpoint
    RENAME COLUMN peer_address TO conversation_address;
ALTER TABLE chat_outbound_archive
    RENAME COLUMN peer_address TO conversation_address;

ALTER TABLE chat_message ADD COLUMN sender_hint BLOB;
ALTER TABLE chat_message ADD COLUMN rx_rssi_dbm INTEGER;
ALTER TABLE chat_message ADD COLUMN rx_snr_cb INTEGER;
ALTER TABLE chat_message ADD COLUMN rx_lqi INTEGER;
ALTER TABLE chat_message ADD COLUMN rx_hop_count INTEGER;
ALTER TABLE chat_message ADD COLUMN rx_route_hints BLOB;
ALTER TABLE chat_message ADD COLUMN rx_source_authenticated INTEGER;

-- Read cursors. Everything created before this migration
-- counts as read: an install that predates unread counts
-- should not open to a wall of unread badges.
ALTER TABLE direct_conversation
    ADD COLUMN last_read_at_ms INTEGER NOT NULL DEFAULT 0;
UPDATE direct_conversation
    SET last_read_at_ms = (
        SELECT COALESCE(MAX(m.created_at_ms), 0) FROM chat_message m
        JOIN node n ON n.public_address = m.conversation_address
        WHERE m.owner_identity_id = direct_conversation.owner_identity_id
          AND n.id = direct_conversation.node_id
    );

-- A channel's group conversation. Separate from
-- `direct_conversation` because its other end is a channel
-- rather than a node, and `node_id` there is a hard
-- reference that cannot be made to mean both.
CREATE TABLE channel_conversation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_identity_id TEXT NOT NULL
        REFERENCES local_identity(id) ON DELETE CASCADE,
    channel_id TEXT NOT NULL REFERENCES channel(id) ON DELETE CASCADE,
    conversation_address TEXT NOT NULL,
    draft_text TEXT NOT NULL DEFAULT '',
    created_at_ms INTEGER NOT NULL,
    last_read_at_ms INTEGER NOT NULL DEFAULT 0,
    UNIQUE (owner_identity_id, channel_id)
);

CREATE INDEX channel_conversation_address_idx
    ON channel_conversation (owner_identity_id, conversation_address);
