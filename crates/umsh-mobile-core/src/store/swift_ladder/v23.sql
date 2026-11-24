-- v23, as the Swift store applied it.
--
-- A path the person chose for a node, held against what the
-- mesh teaches until `hold_until_ms` on the wall clock. The
-- phone's routing keeps routes only in memory, so this is
-- what reinstalls the hold when a session starts. Where the
-- phone stood when the path was saved is what "moved" is
-- measured from; `prompt_settled` remembers that the offer
-- to switch away from this path was declined.
--
-- A frame acknowledged through the flood that followed a
-- missed route is marked, and a message any of whose frames
-- were is marked too, so the transcript can say so.

CREATE TABLE node_manual_route (
    node_id INTEGER PRIMARY KEY REFERENCES node(id) ON DELETE CASCADE,
    hints BLOB NOT NULL,
    hold_until_ms INTEGER NOT NULL,
    saved_latitude REAL,
    saved_longitude REAL,
    saved_accuracy REAL,
    prompt_settled INTEGER NOT NULL DEFAULT 0
);

ALTER TABLE chat_delivery_fragment
    ADD COLUMN via_flood INTEGER NOT NULL DEFAULT 0;
ALTER TABLE chat_message
    ADD COLUMN delivered_flooded INTEGER NOT NULL DEFAULT 0;
