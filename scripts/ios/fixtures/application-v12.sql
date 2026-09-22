-- Frozen schema from 94502d422 (schema version 12). Do not regenerate from the current store.
BEGIN TRANSACTION;
CREATE TABLE chat_applied_mutation (
                        owner_identity_id TEXT NOT NULL
                            REFERENCES local_identity(id) ON DELETE CASCADE,
                        session_id TEXT NOT NULL,
                        handle INTEGER NOT NULL,
                        revision INTEGER NOT NULL,
                        PRIMARY KEY (owner_identity_id, session_id, handle)
                    );
CREATE TABLE chat_delivery_fragment (
                        owner_identity_id TEXT NOT NULL
                            REFERENCES local_identity(id) ON DELETE CASCADE,
                        session_id TEXT NOT NULL,
                        handle INTEGER NOT NULL,
                        fragment_index INTEGER NOT NULL,
                        state TEXT NOT NULL,
                        PRIMARY KEY (
                            owner_identity_id, session_id, handle, fragment_index
                        )
                    );
CREATE TABLE chat_message (
                        owner_identity_id TEXT NOT NULL
                            REFERENCES local_identity(id) ON DELETE CASCADE,
                        session_id TEXT NOT NULL,
                        handle INTEGER NOT NULL,
                        peer_address TEXT NOT NULL,
                        sender_address TEXT,
                        direction INTEGER NOT NULL,
                        message_type INTEGER,
                        wire_id INTEGER,
                        epoch INTEGER,
                        client_token INTEGER,
                        sender_handle TEXT,
                        regarding_handle INTEGER,
                        background_color BLOB,
                        text_color BLOB,
                        body TEXT NOT NULL,
                        complete INTEGER,
                        present_fragments INTEGER,
                        fragment_count INTEGER,
                        finalized INTEGER,
                        delivery_state TEXT,
                        deleted INTEGER NOT NULL DEFAULT 0,
                        created_at_ms INTEGER NOT NULL, edited INTEGER NOT NULL DEFAULT 0, presence INTEGER NOT NULL DEFAULT 0, received_late INTEGER NOT NULL DEFAULT 0, delivered_late INTEGER NOT NULL DEFAULT 0, original_body TEXT,
                        PRIMARY KEY (owner_identity_id, session_id, handle)
                    );
CREATE TABLE chat_outbound_archive (
                        owner_identity_id TEXT NOT NULL
                            REFERENCES local_identity(id) ON DELETE CASCADE,
                        peer_address TEXT NOT NULL,
                        message_id INTEGER NOT NULL,
                        fragment_index INTEGER NOT NULL,
                        payload BLOB NOT NULL,
                        PRIMARY KEY (
                            owner_identity_id, peer_address, message_id, fragment_index
                        )
                    );
CREATE TABLE chat_stream_checkpoint (
                        owner_identity_id TEXT NOT NULL
                            REFERENCES local_identity(id) ON DELETE CASCADE,
                        peer_address TEXT NOT NULL,
                        next_id INTEGER NOT NULL,
                        epoch INTEGER NOT NULL,
                        updated_at_ms INTEGER NOT NULL,
                        PRIMARY KEY (owner_identity_id, peer_address)
                    );
CREATE TABLE direct_conversation (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        owner_identity_id TEXT NOT NULL
                            REFERENCES local_identity(id) ON DELETE CASCADE,
                        node_id INTEGER NOT NULL REFERENCES node(id) ON DELETE RESTRICT,
                        draft_text TEXT NOT NULL DEFAULT '',
                        created_at_ms INTEGER NOT NULL,
                        UNIQUE (owner_identity_id, node_id)
                    );
CREATE TABLE local_identity (
                    id TEXT PRIMARY KEY NOT NULL,
                    public_address TEXT NOT NULL UNIQUE,
                    created_at_ms INTEGER NOT NULL
                , advertised_name TEXT);
CREATE TABLE node (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_identity_id TEXT NOT NULL
                        REFERENCES local_identity(id) ON DELETE CASCADE,
                    public_address TEXT NOT NULL,
                    alias TEXT,
                    alias_search TEXT NOT NULL, advertised_name TEXT, is_contact INTEGER NOT NULL DEFAULT 0, system_role TEXT, radio_identifier TEXT, node_kind TEXT, advertisement BLOB, last_heard_at REAL, advertisement_authenticated INTEGER NOT NULL DEFAULT 0,
                    UNIQUE (owner_identity_id, public_address)
                );
CREATE INDEX node_owner_alias_search_idx
                    ON node (owner_identity_id, alias_search, id);
CREATE INDEX chat_message_conversation_idx
                        ON chat_message (owner_identity_id, peer_address, created_at_ms);
DELETE FROM "sqlite_sequence";
COMMIT;
PRAGMA user_version = 12;

INSERT INTO local_identity (id, public_address, created_at_ms, advertised_name)
VALUES ('alice', 'alice-public', 1000, 'Alice');
INSERT INTO node (id, owner_identity_id, public_address, alias, alias_search, is_contact, advertised_name, advertisement_authenticated)
VALUES (1, 'alice', 'historical-peer', 'Ridge Medic', 'ridge medic', 1, 'Medic', 1);
INSERT INTO direct_conversation (id, owner_identity_id, node_id, draft_text, created_at_ms)
VALUES (1, 'alice', 1, 'Historical draft', 2000);
INSERT INTO chat_message (owner_identity_id, session_id, handle, peer_address, direction, body, created_at_ms)
VALUES ('alice', '42', 1, 'historical-peer', 0, 'Historical message', 3000);
INSERT INTO chat_stream_checkpoint (owner_identity_id, peer_address, next_id, epoch, updated_at_ms)
VALUES ('alice', 'historical-peer', 7, 2, 3000);
INSERT INTO chat_outbound_archive (owner_identity_id, peer_address, message_id, fragment_index, payload)
VALUES ('alice', 'historical-peer', 6, 0, X'010203');
