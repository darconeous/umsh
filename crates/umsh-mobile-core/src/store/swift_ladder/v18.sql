-- v18, as the Swift store applied it.
--
-- What a device said about itself, kept so that opening its
-- settings does not have to ask again. A node several flood
-- hops away answers slowly and at the cost of everyone's
-- airtime, so the phone asks once and remembers.
--
-- `node_mgmt_card` is what a device *is*: capabilities, the
-- firmware they belong to, the hardware, the name. Firmware
-- version is the key the rest hangs from—capabilities
-- cannot change without it changing too—so a card arriving
-- with a different version invalidates every cached value
-- alongside it.
--
-- `node_prop_cache` is what a device was last seen configured
-- as, verbatim: the bytes the device sent, decoded in Rust
-- where the wire formats already live. `fetched_at_ms` is
-- what lets a screen admit its age rather than present a
-- stale reading as current.

CREATE TABLE node_mgmt_card (
    node_id INTEGER PRIMARY KEY REFERENCES node(id) ON DELETE CASCADE,
    capabilities BLOB NOT NULL,
    device_version TEXT,
    device_model TEXT,
    device_name TEXT,
    fetched_at_ms INTEGER NOT NULL
);

CREATE TABLE node_prop_cache (
    node_id INTEGER NOT NULL REFERENCES node(id) ON DELETE CASCADE,
    property_id INTEGER NOT NULL,
    value BLOB NOT NULL,
    fetched_at_ms INTEGER NOT NULL,
    PRIMARY KEY (node_id, property_id)
) WITHOUT ROWID;
