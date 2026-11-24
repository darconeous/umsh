-- v2, as the Swift store applied it.

ALTER TABLE node ADD COLUMN advertised_name TEXT;
ALTER TABLE node ADD COLUMN is_contact INTEGER NOT NULL DEFAULT 0;
ALTER TABLE node ADD COLUMN system_role TEXT;
ALTER TABLE node ADD COLUMN radio_identifier TEXT;

CREATE TABLE direct_conversation (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_identity_id TEXT NOT NULL
        REFERENCES local_identity(id) ON DELETE CASCADE,
    node_id INTEGER NOT NULL REFERENCES node(id) ON DELETE RESTRICT,
    draft_text TEXT NOT NULL DEFAULT '',
    created_at_ms INTEGER NOT NULL,
    UNIQUE (owner_identity_id, node_id)
);
