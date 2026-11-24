-- v31, as the Swift store applied it.
--
-- Radios this phone left holding its identity as their
-- host, so it can revoke them from wherever it next attaches.
-- Keyed by device address, which outlives a radio's name and
-- its Bluetooth identifier.

CREATE TABLE claimed_radio (
    owner_identity_id TEXT NOT NULL
        REFERENCES local_identity(id) ON DELETE CASCADE,
    device_address TEXT NOT NULL,
    name TEXT,
    attached_at_ms INTEGER NOT NULL,
    PRIMARY KEY (owner_identity_id, device_address)
) WITHOUT ROWID;
