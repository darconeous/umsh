import Foundation

@main
struct PersistenceSmokeTest {
    static func main() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("umsh-persistence-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let databaseURL = root.appendingPathComponent("application.sqlite")

        let store = try SQLiteApplicationStore(path: databaseURL.path)
        let initialSchemaVersion = try await store.schemaVersion()
        precondition(initialSchemaVersion == 3)

        try await store.insertIdentity(id: "alice", publicAddress: "alice-public")
        try await store.insertIdentity(id: "bob", publicAddress: "bob-public")

        try await store.insertNodesAtomically(
            ownerIdentityID: "alice",
            nodes: [
                NewStoredNode(publicAddress: "peer-one", alias: "Ridge Medic"),
                NewStoredNode(publicAddress: "peer-two", alias: "River Base"),
            ]
        )
        try await store.insertNodesAtomically(
            ownerIdentityID: "bob",
            nodes: [NewStoredNode(publicAddress: "peer-one", alias: "Bob's Ridge Medic")]
        )

        do {
            try await store.insertNodesAtomically(
                ownerIdentityID: "alice",
                nodes: [
                    NewStoredNode(publicAddress: "rolled-back", alias: "Temporary"),
                    NewStoredNode(publicAddress: "peer-one", alias: "Duplicate"),
                ]
            )
            preconditionFailure("Identity-scoped duplicate unexpectedly committed")
        } catch ApplicationStoreError.sqliteFailure {
            // The duplicate must roll back the entire batch.
        }
        let rolledBack = try await store.searchNodes(ownerIdentityID: "alice", aliasPrefix: "Temp")
        precondition(rolledBack.isEmpty)

        do {
            try await store.insertNodesAtomically(
                ownerIdentityID: "missing",
                nodes: [NewStoredNode(publicAddress: "orphan", alias: nil)]
            )
            preconditionFailure("Foreign-key violation unexpectedly committed")
        } catch ApplicationStoreError.sqliteFailure {
            // Expected.
        }

        let ridge = try await store.searchNodes(ownerIdentityID: "alice", aliasPrefix: "ridge")
        precondition(ridge.map(\.publicAddress) == ["peer-one"])
        let searchUsesIndex = try await store.nodeSearchUsesIndex(
            ownerIdentityID: "alice",
            aliasPrefix: "ridge"
        )
        precondition(searchUsesIndex)

        let reopened = try SQLiteApplicationStore(path: databaseURL.path)
        let reopenedSchemaVersion = try await reopened.schemaVersion()
        precondition(reopenedSchemaVersion == 3)
        let persisted = try await reopened.searchNodes(ownerIdentityID: "alice", aliasPrefix: "river")
        precondition(persisted.map(\.publicAddress) == ["peer-two"])

        try await reopened.upsertPeer(
            ownerIdentityID: "alice",
            publicAddress: "peer-three",
            alias: "Hill Relay",
            isContact: true,
            nodeKind: "repeater"
        )
        let conversationID = try await reopened.ensureDirectConversation(
            ownerIdentityID: "alice",
            peerAddress: "peer-three"
        )
        try await reopened.updateDraft(
            ownerIdentityID: "alice",
            conversationID: conversationID,
            text: "Draft survives relaunch"
        )
        let conversations = try await reopened.listDirectConversations(ownerIdentityID: "alice")
        precondition(conversations.count == 1)
        precondition(conversations[0].node.alias == "Hill Relay")
        precondition(conversations[0].node.nodeKind == "repeater")
        precondition(conversations[0].draftText == "Draft survives relaunch")

        try await reopened.insertIdentity(id: "primary", publicAddress: "legacy-public")
        try await reopened.upsertPeer(
            ownerIdentityID: "primary",
            publicAddress: "legacy-peer",
            alias: "Legacy Peer",
            isContact: true
        )
        let legacyConversation = try await reopened.ensureDirectConversation(
            ownerIdentityID: "primary",
            peerAddress: "legacy-peer"
        )
        try await reopened.updateDraft(
            ownerIdentityID: "primary",
            conversationID: legacyConversation,
            text: "Keep this"
        )
        try await reopened.migrateLegacyPrimaryIdentity(
            to: "legacy-public",
            publicAddress: "legacy-public"
        )
        let migratedNodes = try await reopened.listNodes(ownerIdentityID: "legacy-public")
        precondition(migratedNodes.map(\.publicAddress) == ["legacy-peer"])
        let migratedConversations = try await reopened.listDirectConversations(
            ownerIdentityID: "legacy-public"
        )
        precondition(migratedConversations.count == 1)
        precondition(migratedConversations[0].draftText == "Keep this")

        print("SQLite peer, conversation, draft, migration, and transaction checks passed")
    }
}
