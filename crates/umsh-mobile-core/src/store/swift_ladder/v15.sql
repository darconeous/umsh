-- v15, as the Swift store applied it.
--
-- Channel membership. The row is public metadata; the 32-byte
-- key it describes lives in Keychain under `id`.
--
-- `channel_id_hex` is the two-octet derived identifier, which
-- is a routing hint and NOT unique—distinct keys may collide
-- and receivers resolve that by trial decryption—so it
-- cannot key the table. `key_digest` can: it is a one-way
-- commitment to the key that makes "already joined" and "same
-- name, different key" answerable in SQL, without which an
-- import would have to unlock every stored key to compare.

CREATE TABLE channel (
    id TEXT PRIMARY KEY NOT NULL,
    owner_identity_id TEXT NOT NULL
        REFERENCES local_identity(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    canonical_name TEXT,
    name TEXT,
    alias TEXT,
    channel_id_hex TEXT NOT NULL,
    tint BLOB NOT NULL,
    key_digest TEXT NOT NULL,
    region_code BLOB,
    max_flood_hops INTEGER,
    joined_phone INTEGER NOT NULL DEFAULT 0,
    joined_device INTEGER NOT NULL DEFAULT 0,
    notifications_enabled INTEGER NOT NULL DEFAULT 0,
    created_at_ms INTEGER NOT NULL,
    joined_at_ms INTEGER,
    UNIQUE (owner_identity_id, key_digest)
);

CREATE INDEX channel_owner_idx ON channel (owner_identity_id, id);
