-- v1, as the Swift store applied it.

CREATE TABLE local_identity (
    id TEXT PRIMARY KEY NOT NULL,
    public_address TEXT NOT NULL UNIQUE,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE node (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_identity_id TEXT NOT NULL
        REFERENCES local_identity(id) ON DELETE CASCADE,
    public_address TEXT NOT NULL,
    alias TEXT,
    alias_search TEXT NOT NULL,
    UNIQUE (owner_identity_id, public_address)
);

CREATE INDEX node_owner_alias_search_idx
    ON node (owner_identity_id, alias_search, id);
