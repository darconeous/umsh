-- v17, as the Swift store applied it.
--
-- Reactions are emotes: ordinary messages carrying a Regarding
-- reference, which is why they live in `chat_message` rather
-- than a table of their own—they are sent, delivered,
-- acknowledged, and repaired like anything else. What they need
-- is somewhere to record who they are about, resolved once on
-- arrival: the wire columns say what the frame claimed, and the
-- `reaction_target_*` pair says which stored row that turned out
-- to be. Reactions whose target has not arrived yet keep the
-- pair null until it does.

ALTER TABLE chat_message ADD COLUMN is_reaction INTEGER NOT NULL DEFAULT 0;
ALTER TABLE chat_message ADD COLUMN regarding_wire_id INTEGER;
ALTER TABLE chat_message ADD COLUMN regarding_direction INTEGER;
ALTER TABLE chat_message ADD COLUMN regarding_sender_hint BLOB;
ALTER TABLE chat_message ADD COLUMN reaction_target_session_id TEXT;
ALTER TABLE chat_message ADD COLUMN reaction_target_handle INTEGER;

CREATE INDEX chat_message_reaction_target_idx
    ON chat_message (
        owner_identity_id,
        reaction_target_session_id,
        reaction_target_handle
    )
    WHERE is_reaction = 1;
