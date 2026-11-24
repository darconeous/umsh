-- v24, as the Swift store applied it.
--
-- How far a held path floods past its last repeater. Paths
-- saved before this had the routing layer's one hop of slack.

ALTER TABLE node_manual_route
    ADD COLUMN flood_hops INTEGER NOT NULL DEFAULT 1;
