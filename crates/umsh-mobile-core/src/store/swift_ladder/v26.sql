-- v26, as the Swift store applied it.
--
-- A reply names the message it answers just as a reaction
-- does, so the resolved target is the Regarding reference's,
-- not the reaction's. Replies stored before this kept their
-- reference unresolved; resolve them the way an arriving
-- one is. The wire lookup now runs for every reply, so it
-- gets an index.

ALTER TABLE chat_message
    RENAME COLUMN reaction_target_session_id TO regarding_target_session_id;
ALTER TABLE chat_message
    RENAME COLUMN reaction_target_handle TO regarding_target_handle;

UPDATE chat_message
SET regarding_target_session_id = session_id,
    regarding_target_handle = regarding_handle
WHERE is_reaction = 0
    AND regarding_target_session_id IS NULL
    AND regarding_handle IS NOT NULL;

UPDATE chat_message AS reply
SET (regarding_target_session_id, regarding_target_handle) = (
    SELECT target.session_id, target.handle FROM chat_message AS target
    WHERE target.owner_identity_id = reply.owner_identity_id
        AND target.conversation_address = reply.conversation_address
        AND target.direction = reply.regarding_direction
        AND target.wire_id = reply.regarding_wire_id
        AND target.is_reaction = 0
        AND target.sender_hint IS reply.regarding_sender_hint
        AND target.rowid <> reply.rowid
    ORDER BY target.epoch DESC, target.created_at_ms DESC, target.rowid DESC
    LIMIT 1
)
WHERE is_reaction = 0
    AND regarding_target_session_id IS NULL
    AND regarding_wire_id IS NOT NULL;

CREATE INDEX chat_message_wire_idx
    ON chat_message (owner_identity_id, conversation_address, direction, wire_id);
