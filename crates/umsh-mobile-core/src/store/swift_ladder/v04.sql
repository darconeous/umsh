-- v4, as the Swift store applied it.

CREATE TABLE chat_stream_checkpoint (
    owner_identity_id TEXT NOT NULL
        REFERENCES local_identity(id) ON DELETE CASCADE,
    peer_address TEXT NOT NULL,
    next_id INTEGER NOT NULL,
    epoch INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    PRIMARY KEY (owner_identity_id, peer_address)
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
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (owner_identity_id, session_id, handle)
);

CREATE INDEX chat_message_conversation_idx
    ON chat_message (owner_identity_id, peer_address, created_at_ms);

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
