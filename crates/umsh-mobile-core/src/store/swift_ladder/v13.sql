-- v13, as the Swift store applied it.
--
-- The peer tier model: `is_saved` marks a node stored on the
-- local (phone) identity; rows with 0 are the transient tier—
-- heard on the air, kept for search/discovery, hidden from the
-- main list, and evicted by retention. `on_dev_identity` caches
-- whether the node's key is on the companion radio's device
-- identity (PROP_DEV_PEERS); the device is the authority.
-- Every pre-existing row was visible in Peers, so all of
-- them upgrade as saved—nothing may vanish from the list.

ALTER TABLE node ADD COLUMN is_saved INTEGER NOT NULL DEFAULT 0;
ALTER TABLE node ADD COLUMN is_favorite INTEGER NOT NULL DEFAULT 0;
ALTER TABLE node ADD COLUMN on_dev_identity INTEGER NOT NULL DEFAULT 0;
UPDATE node SET is_saved = 1;
CREATE INDEX node_owner_transient_heard_idx
    ON node (owner_identity_id, is_saved, last_heard_at);
