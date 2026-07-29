import Foundation
import SQLite3

@main
struct PersistenceSmokeTest {
    static func main() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("umsh-persistence-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let databaseURL = root.appendingPathComponent("application.sqlite")

        var store = try SQLiteApplicationStore(path: databaseURL.path)
        let initialSchemaVersion = try await store.schemaVersion()
        precondition(initialSchemaVersion == SQLiteApplicationStore.currentSchemaVersion)

        try await store.insertIdentity(id: "alice", publicAddress: "alice-public")

        // A user-initiated import is saved; a contact is saved by definition.
        try await store.upsertPeer(
            ownerIdentityID: "alice",
            publicAddress: "peer-contact",
            alias: "Ridge Medic",
            isContact: true
        )
        // An over-the-air advertisement lands in the transient tier.
        try await store.upsertPeer(
            ownerIdentityID: "alice",
            publicAddress: "peer-transient",
            alias: nil,
            advertisedName: "Roaming Node",
            isContact: false
        )
        var nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(node(nodes, "peer-contact").isSaved)
        precondition(node(nodes, "peer-contact").isContact)
        precondition(!node(nodes, "peer-transient").isSaved)

        // A background advertisement upsert must never demote a saved peer.
        try await store.upsertPeer(
            ownerIdentityID: "alice",
            publicAddress: "peer-contact",
            alias: nil,
            advertisedName: "Ridge Medic Node",
            isContact: false
        )
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(node(nodes, "peer-contact").isSaved)
        precondition(node(nodes, "peer-contact").isContact)

        // Promote a transient; favorite it (favoriting implies saved).
        try await store.promotePeerToSaved(ownerIdentityID: "alice", publicAddress: "peer-transient")
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(node(nodes, "peer-transient").isSaved)
        try await store.setPeerFavorite(
            ownerIdentityID: "alice",
            publicAddress: "peer-transient",
            isFavorite: true
        )
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(node(nodes, "peer-transient").isFavorite)

        // Demote clears contact/favorite/alias but keeps the row.
        try await store.demotePeerToTransient(ownerIdentityID: "alice", publicAddress: "peer-contact")
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(!node(nodes, "peer-contact").isSaved)
        precondition(!node(nodes, "peer-contact").isContact)
        precondition(node(nodes, "peer-contact").alias == nil)
        try await store.promotePeerToSaved(ownerIdentityID: "alice", publicAddress: "peer-contact")

        // Delete refuses a peer with a conversation; the combined delete works
        // and removes both.
        let conversationID = try await store.ensureDirectConversation(
            ownerIdentityID: "alice",
            peerAddress: "peer-contact"
        )
        try await store.updateDraft(
            ownerIdentityID: "alice",
            conversationID: conversationID,
            text: "Draft survives relaunch"
        )
        let conversations = try await store.listDirectConversations(ownerIdentityID: "alice")
        precondition(conversations.count == 1)
        precondition(conversations[0].draftText == "Draft survives relaunch")
        let refused = try await store.deletePeer(ownerIdentityID: "alice", publicAddress: "peer-contact")
        precondition(!refused)
        let removed = try await store.deletePeerAndConversation(
            ownerIdentityID: "alice",
            publicAddress: "peer-contact"
        )
        precondition(removed)
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(!nodes.contains { $0.publicAddress == "peer-contact" })
        let remainingConversations = try await store.listDirectConversations(ownerIdentityID: "alice")
        precondition(remainingConversations.isEmpty)

        // Plain delete works for a peer without a conversation.
        let deleted = try await store.deletePeer(ownerIdentityID: "alice", publicAddress: "peer-transient")
        precondition(deleted)

        // The companion radio row is protected from delete and demote.
        try await store.upsertUlcpDevicePeer(
            ownerIdentityID: "alice",
            publicAddress: "radio-peer",
            advertisedName: "Tracker",
            radioIdentifier: "AAAA"
        )
        let radioDeleted = try await store.deletePeer(ownerIdentityID: "alice", publicAddress: "radio-peer")
        precondition(!radioDeleted)
        try await store.demotePeerToTransient(ownerIdentityID: "alice", publicAddress: "radio-peer")
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(node(nodes, "radio-peer").isSaved)

        // Retention keeps the newest-heard transients up to the cap; rows with
        // a conversation are never evicted. clearTransientPeers drops the rest.
        for index in 0..<5 {
            let address = "flood-\(index)"
            try await store.upsertPeer(
                ownerIdentityID: "alice",
                publicAddress: address,
                alias: nil,
                isContact: false
            )
            try await store.touchLastHeard(
                ownerIdentityID: "alice",
                publicAddress: address,
                at: Date(timeIntervalSince1970: 1_000 + Double(index))
            )
        }
        _ = try await store.ensureDirectConversation(ownerIdentityID: "alice", peerAddress: "flood-0")
        try await store.enforceTransientRetention(ownerIdentityID: "alice", cap: 2)
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        let survivingTransients = nodes.filter { $0.publicAddress.hasPrefix("flood-") }
        // flood-0 survives via its conversation; flood-4 and flood-3 are the
        // two newest-heard evictable rows.
        precondition(
            Set(survivingTransients.map(\.publicAddress)) == ["flood-0", "flood-3", "flood-4"]
        )
        try await store.clearTransientPeers(ownerIdentityID: "alice")
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(
            Set(nodes.filter { $0.publicAddress.hasPrefix("flood-") }.map(\.publicAddress))
                == ["flood-0"]
        )

        // Device-identity reconcile: the device's read-back is authority.
        // Known keys gain the flag, unknown keys gain a transient row, and
        // keys absent from the list lose the flag (rows survive).
        try await store.reconcileDeviceIdentityPeers(
            ownerIdentityID: "alice",
            addresses: ["flood-0", "device-only-peer"]
        )
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(node(nodes, "flood-0").onDeviceIdentity)
        let deviceOnly = node(nodes, "device-only-peer")
        precondition(deviceOnly.onDeviceIdentity && !deviceOnly.isSaved)
        try await store.reconcileDeviceIdentityPeers(ownerIdentityID: "alice", addresses: [])
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(nodes.allSatisfy { !$0.onDeviceIdentity })
        precondition(nodes.contains { $0.publicAddress == "device-only-peer" })
        // The single-flag cache setter round-trips too.
        try await store.setPeerOnDeviceIdentity(
            ownerIdentityID: "alice",
            publicAddress: "flood-0",
            isOnDeviceIdentity: true
        )
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(node(nodes, "flood-0").onDeviceIdentity)
        try await store.setPeerOnDeviceIdentity(
            ownerIdentityID: "alice",
            publicAddress: "flood-0",
            isOnDeviceIdentity: false
        )
        try await store.deletePeer(ownerIdentityID: "alice", publicAddress: "device-only-peer")

        // Legacy "primary" identity migration still transfers records intact.
        try await store.insertIdentity(id: "primary", publicAddress: "legacy-public")
        try await store.upsertPeer(
            ownerIdentityID: "primary",
            publicAddress: "legacy-peer",
            alias: "Legacy Peer",
            isContact: true
        )
        try await store.migrateLegacyPrimaryIdentity(
            to: "legacy-public",
            publicAddress: "legacy-public"
        )
        let migratedNodes = try await store.listNodes(ownerIdentityID: "legacy-public")
        precondition(migratedNodes.map(\.publicAddress) == ["legacy-peer"])

        // v12 → v13 upgrade on a populated database: strip the v13 columns and
        // stamp user_version 12, then reopen. Nothing may vanish, and every
        // pre-existing row must upgrade as saved.
        store = try SQLiteApplicationStore(path: databaseURL.path)
        try await store.demotePeerToTransient(ownerIdentityID: "alice", publicAddress: "flood-0")
        try downgradeToV12(path: databaseURL.path)
        let reopened = try SQLiteApplicationStore(path: databaseURL.path)
        let reopenedSchemaVersion = try await reopened.schemaVersion()
        precondition(reopenedSchemaVersion == SQLiteApplicationStore.currentSchemaVersion)
        let upgraded = try await reopened.listNodes(ownerIdentityID: "alice")
        precondition(upgraded.contains { $0.publicAddress == "flood-0" })
        precondition(upgraded.allSatisfy(\.isSaved))
        precondition(upgraded.allSatisfy { !$0.isFavorite && !$0.onDeviceIdentity })

        print("SQLite tier, delete/demote, retention, migration, and upgrade checks passed")
    }

    private static func node(_ nodes: [StoredNode], _ address: String) -> StoredNode {
        guard let found = nodes.first(where: { $0.publicAddress == address }) else {
            preconditionFailure("Missing expected node \(address)")
        }
        return found
    }

    /// Rewind a v13 database to the v12 shape so the migration path from a
    /// populated store is exercised for real.
    private static func downgradeToV12(path: String) throws {
        var connection: OpaquePointer?
        precondition(sqlite3_open(path, &connection) == SQLITE_OK, "downgrade open failed")
        defer { sqlite3_close(connection) }
        let sql = """
            DROP INDEX node_owner_transient_heard_idx;
            ALTER TABLE node DROP COLUMN is_saved;
            ALTER TABLE node DROP COLUMN is_favorite;
            ALTER TABLE node DROP COLUMN on_dev_identity;
            PRAGMA user_version = 12;
            """
        precondition(
            sqlite3_exec(connection, sql, nil, nil, nil) == SQLITE_OK,
            "downgrade DDL failed: \(String(cString: sqlite3_errmsg(connection)))"
        )
    }
}
