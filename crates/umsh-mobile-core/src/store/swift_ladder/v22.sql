-- v22, as the Swift store applied it.
--
-- What a repeater last said about its neighbors, page by page.
-- Cached for the same reason a device's properties are: every
-- page is a mesh exchange at everyone's expense, so the
-- screen opens on what was last heard and asks only when
-- told to. The header holds where the next page starts; the
-- entries are keyed by hint so a page the repeater repeats
-- updates rows rather than doubling them. Both go with the
-- node's row.

CREATE TABLE node_peer_repeaters (
    node_id INTEGER PRIMARY KEY REFERENCES node(id) ON DELETE CASCADE,
    total INTEGER,
    next_cursor BLOB,
    as_of_ms INTEGER NOT NULL
);

CREATE TABLE node_peer_repeater_entry (
    node_id INTEGER NOT NULL REFERENCES node(id) ON DELETE CASCADE,
    hint BLOB NOT NULL,
    position INTEGER NOT NULL,
    name TEXT,
    rssi_dbm INTEGER,
    snr_quarter_db INTEGER,
    last_heard_min INTEGER,
    latitude REAL,
    longitude REAL,
    location_precision INTEGER,
    region_codes BLOB,
    reported_at_ms INTEGER NOT NULL,
    PRIMARY KEY (node_id, hint)
) WITHOUT ROWID;
