import Foundation
import SQLite3
import Testing
import UMSHMobileCore
@testable import UMSH

/// Renders what the app shows of the committed parity stores, read through a
/// radio-less `MobileAppCore` and mapped by `CoreRecordMapping`, and holds it
/// to the goldens. The format is the contract in
/// `crates/umsh-mobile-core/src/app_core/parity/README.md`; the core's own
/// parity test owns the goldens, so nothing here writes them.
@Suite @MainActor
struct ReadMappingParityTests {
    private static let directory = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("crates/umsh-mobile-core/src/app_core/parity")

    @Test(arguments: [("seeded", "owner"), ("augmented", "alice")])
    func goldenMatches(store name: String, owner: String) async throws {
        let rendered = try await Self.render(store: name, owner: owner)
        let golden = Self.directory.appendingPathComponent("\(name).golden")
        let expected = try String(contentsOf: golden, encoding: .utf8)
        guard rendered != expected else { return }
        let ours = rendered.split(separator: "\n", omittingEmptySubsequences: false)
        let theirs = expected.split(separator: "\n", omittingEmptySubsequences: false)
        let index = zip(ours, theirs).enumerated().first { $0.element.0 != $0.element.1 }?.offset
            ?? min(ours.count, theirs.count)
        let got = index < ours.count ? String(ours[index]) : "<end>"
        let want = index < theirs.count ? String(theirs[index]) : "<end>"
        Issue.record("\(name).golden differs at line \(index + 1):\n  got:  \(got)\n  want: \(want)")
    }

    // MARK: - Loading

    private static func render(store name: String, owner: String) async throws -> String {
        // Opening migrates in place, so only ever open a copy.
        let copy = FileManager.default.temporaryDirectory
            .appendingPathComponent("parity-\(name)-\(UUID().uuidString).sqlite")
        try FileManager.default.copyItem(at: directory.appendingPathComponent("\(name).sqlite"), to: copy)
        defer {
            for suffix in ["", "-wal", "-shm"] {
                try? FileManager.default.removeItem(atPath: copy.path + suffix)
            }
        }
        let store = try SQLiteApplicationStore(path: copy.path)
        let runtime = try radioLessRuntime(store: store)
        let publicAddress = try query(copy, "SELECT public_address FROM local_identity WHERE id = ?", owner).first ?? owner
        // Nothing in the read mapping looks at the owner's own identity, and
        // the augmented owner's address does not decode.
        let publicIdentity = (try? await RustMeshEngine().inspectPublicIdentity(publicAddress))
            ?? MeshPublicIdentity(canonicalAddress: publicAddress, hint: MeshNodeHint(bytes: Data(), text: ""))
        runtime.localIdentity = LocalIdentitySnapshot(id: owner, publicIdentity: publicIdentity)
        await runtime.reloadApplicationState()
        #expect(runtime.stateLoadError == nil)

        var lines: [String] = []
        lines.append("## state")
        lines += stateLines(runtime).sorted(by: bytewise)

        let addresses = try query(copy,
            "SELECT DISTINCT conversation_address FROM chat_message WHERE owner_identity_id = ?", owner)
        for address in addresses.sorted(by: bytewise) {
            let page = await runtime.transcriptLoader.newest(address, 500)
            lines.append("## transcript \(address)")
            lines.append("page has_older=\(bool(page.hasOlder)) has_newer=\(bool(page.hasNewer))")
            lines += page.messages.map { messageLine($0, peers: runtime.peers) }
        }

        let cached = try #require(runtime.peerActions.cachedPeerRepeaters)
        var listings: [(String, PeerRepeaterListing)] = []
        for peer in runtime.peers {
            if let listing = await cached(peer) { listings.append((peer.identity.canonicalAddress, listing)) }
        }
        for (address, listing) in listings.sorted(by: { bytewise($0.0, $1.0) }) {
            lines.append("## repeaters \(address)")
            lines.append("listing total=\(opt(listing.total, int)) next_cursor=\(opt(listing.nextCursor, bytes)) as_of=\(ms(listing.asOf))")
            lines += listing.entries.map { "entry " + neighbor($0, peers: runtime.peers) }
        }
        return lines.joined(separator: "\n") + "\n"
    }

    /// Distinct text values of a one-column query against the store copy.
    private static func query(_ url: URL, _ sql: String, _ argument: String) throws -> [String] {
        var db: OpaquePointer?
        guard sqlite3_open_v2(url.path, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else { throw ParityFailure.sqlite }
        defer { sqlite3_close(db) }
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &statement, nil) == SQLITE_OK else { throw ParityFailure.sqlite }
        defer { sqlite3_finalize(statement) }
        let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(statement, 1, argument, -1, transient)
        var values: [String] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            if let text = sqlite3_column_text(statement, 0) { values.append(String(cString: text)) }
        }
        return values
    }

    private enum ParityFailure: Error { case sqlite }

    // MARK: - State

    private static func stateLines(_ runtime: AppRuntime) -> [String] {
        var lines: [String] = []
        for peer in runtime.peers {
            let role: String? = peer.storedRole == .unknown ? nil : peer.storedRole.rawValue.lowercased()
            lines.append("peer id=\(peer.id) address=\(str(peer.identity.canonicalAddress))"
                + " hint=\(str(peer.identity.hint.text)) alias=\(opt(peer.alias, str))"
                + " advertised_name=\(opt(peer.advertisedName, str))"
                + " system_role=\(opt(peer.systemRole, systemRole)) node_kind=\(role ?? "-")"
                + " advertised=\(opt(peer.advertisedIdentity, identity))"
                + " authenticated=\(bool(peer.advertisedIdentityAuthenticated))"
                + " received_at=\(opt(peer.advertisedIdentityReceivedAt, ms))"
                + " last_heard=\(opt(peer.lastHeard, ms)) saved=\(bool(peer.isSaved))"
                + " favorite=\(bool(peer.isFavorite)) on_device=\(bool(peer.isOnDeviceIdentity))"
                + " notify_when_heard=\(bool(peer.notifyWhenHeard))")
        }
        for channel in runtime.channels {
            lines.append("channel id=\(str(channel.id.uuidString)) kind=\(channelKind(channel.kind))"
                + " canonical_name=\(opt(channel.canonicalName, str)) name=\(opt(channel.name, str))"
                + " alias=\(opt(channel.alias, str)) channel_id_hex=\(str(channel.channelIDHex))"
                + " tint=\(bytes(channel.tint)) region_code=\(opt(channel.regionCode, bytes))"
                + " max_flood_hops=\(opt(channel.maxFloodHops, int))"
                + " joined_phone=\(bool(channel.joinedPhone))"
                + " notifications=\(bool(channel.notificationsEnabled)) joined_at=\(opt(channel.joinedAt, ms))")
        }
        for conversation in runtime.conversations {
            lines.append("direct id=\(conversation.id) peer=\(str(conversation.peer.identity.canonicalAddress))"
                + " draft=\(str(conversation.draftText)) unread=\(conversation.unreadCount)"
                + " created=\(conversation.createdAtMilliseconds)"
                + " notifications=\(bool(conversation.notificationsEnabled))"
                + " last=\(opt(conversation.lastMessage, preview))")
        }
        for conversation in runtime.channelConversations {
            lines.append("channel_conversation id=\(conversation.id)"
                + " channel=\(str(conversation.channel.id.uuidString))"
                + " address=\(str(conversation.conversationAddress)) draft=\(str(conversation.draftText))"
                + " unread=\(conversation.unreadCount) created=\(conversation.createdAtMilliseconds)"
                + " last=\(opt(conversation.lastMessage, preview))")
        }
        for report in runtime.neighborReports {
            lines.append("report reporter=\(str(report.reporter.identity.canonicalAddress))"
                + " neighbor=\(neighbor(report.neighbor, peers: runtime.peers))")
        }
        return lines
    }

    private static func identity(_ value: MeshNodeIdentity) -> String {
        record([
            ("role", int(value.roleCode)), ("capabilities", int(value.capabilityBits.rawValue)),
            ("forwards", bool(value.forwards)), ("name", opt(value.name, str)),
            ("latitude", opt(value.latitude, float)), ("longitude", opt(value.longitude, float)),
            ("precision", opt(value.locationPrecision, int)), ("altitude", opt(value.altitudeMeters, int)),
            ("timestamp", opt(value.timestamp, int)), ("signature", signature(value.signature)),
        ])
    }

    private static func preview(_ value: ConversationPreviewMessage) -> String {
        record([
            ("created", int(value.createdAtMilliseconds)), ("body", str(value.body)),
            ("outbound", bool(value.isOutbound)), ("deleted", bool(value.isDeleted)),
            ("sender_address", opt(value.senderAddress, str)), ("sender_hint", opt(value.senderHint, bytes)),
            ("status", bool(value.isStatus)), ("sender_node_hint", opt(value.senderNodeHint?.text, str)),
        ])
    }

    private static func neighbor(_ value: PeerRepeaterNeighbor, peers: [PeerSummary]) -> String {
        record([
            ("hint", bytes(value.hint)), ("hint_text", str(value.hintText)), ("name", opt(value.name, str)),
            ("rssi", opt(value.rssiDBm, int)), ("snr", opt(value.snrQuarterDB, int)),
            ("last_heard_minutes", opt(value.lastHeardMinutes, int)),
            ("latitude", opt(value.latitude, float)), ("longitude", opt(value.longitude, float)),
            ("precision", opt(value.locationPrecision, int)), ("regions", list(value.regionCodes.map(bytes))),
            ("reported_at", ms(value.reportedAt)),
            ("peer", opt(value.resolve(among: peers)?.identity.canonicalAddress, str)),
        ])
    }

    // MARK: - Transcript

    private static func messageLine(_ message: ChatMessageSummary, peers: [PeerSummary]) -> String {
        "message id=\(str(message.id))"
            + " cursor=\(message.cursor.createdAtMilliseconds)/\(message.cursor.rowID)"
            + " created=\(message.createdAtMilliseconds) body=\(str(message.body))"
            + " outbound=\(bool(message.isOutbound)) delivery=\(opt(message.deliveryState, delivery))"
            + " deleted=\(bool(message.isDeleted)) edited=\(bool(message.isEdited))"
            + " wire=\(opt(message.wireID, int)) epoch=\(opt(message.epoch, int))"
            + " presence=\(presence(message)) received_late=\(bool(message.isReceivedLate))"
            + " delivered_late=\(bool(message.isDeliveredLate))"
            + " delivered_flooded=\(bool(message.isDeliveredFlooded))"
            + " edit_of_unknown=\(bool(message.isEditOfUnknown)) status=\(bool(message.isStatus))"
            + " forward_secret=\(bool(message.isForwardSecret))"
            + " original_body=\(opt(message.originalBody, str))"
            + " sender_address=\(opt(message.senderAddress, str))"
            + " sender_hint=\(opt(message.senderHint, bytes))"
            + " sender_handle=\(opt(message.senderHandle, str))"
            + " sender_node_hint=\(opt(message.senderNodeHint?.text, str))"
            + " reception=\(opt(message.reception, reception))"
            + " reactions=\(list(message.reactions.map(reaction)))"
            + " quote=\(opt(message.reply, quote))"
            + " repeats=\(opt(message.repeats) { repeats($0, peers: peers) })"
    }

    private static func presence(_ message: ChatMessageSummary) -> String {
        if message.isGapIdle { return "gapidle" }
        if message.isUnavailable { return "unavailable" }
        if message.isGapPlaceholder { return "gappending" }
        return "present"
    }

    private static func reception(_ value: StoredMessageReception) -> String {
        record([
            ("rssi", opt(value.rssiDbm, int)), ("snr", opt(value.snrCentibels, int)),
            ("lqi", opt(value.lqi, int)), ("hops", opt(value.hopCount, int)),
            ("routes", list(value.routeHints.map(bytes))), ("authenticated", bool(value.sourceAuthenticated)),
        ])
    }

    private static func reaction(_ value: MessageReaction) -> String {
        record([
            ("body", str(value.body)), ("mine", bool(value.isMine)),
            ("sender_address", opt(value.senderAddress, str)), ("sender_hint", opt(value.senderHint, bytes)),
            ("target", str(value.id)), ("wire", opt(value.wireID, int)), ("epoch", opt(value.epoch, int)),
            ("failed", bool(value.isFailed)), ("forward_secret", bool(value.isForwardSecret)),
        ])
    }

    private static func quote(_ value: MessageQuote) -> String {
        let state: String
        switch value.state {
        case .unavailable: return "unavailable"
        case .present: state = "present"
        case .deleted: state = "deleted"
        }
        return record([
            ("state", state), ("target", opt(value.targetID, str)), ("body", str(value.body)),
            ("outbound", bool(value.isOutbound)), ("sender_address", opt(value.senderAddress, str)),
            ("sender_handle", opt(value.senderHandle, str)),
            ("sender_node_hint", opt(value.senderNodeHint?.text, str)),
        ])
    }

    private static func repeats(_ value: MessageRepeats, peers: [PeerSummary]) -> String {
        let repeaters = value.repeaters.map { repeater in
            // The app names only a hint the core rendered; an unrendered
            // hint keeps its hex fallback and no name, so no peer either.
            let peer = repeater.name == nil ? nil : RepeaterHintNaming.match(repeater.hint, among: peers)
            // The app keeps only the name; the address is the same match's.
            #expect(peer?.displayName == repeater.name)
            return record([
                ("hint", bytes(repeater.hint.bytes)), ("text", str(repeater.hint.text)),
                ("peer", opt(peer?.identity.canonicalAddress, str)),
            ])
        }
        return record([
            ("anonymous", int(value.anonymous)), ("progress_at", ms(value.progressAt)),
            ("repeaters", list(repeaters)),
        ])
    }

    // MARK: - Values

    private static func bytewise(_ lhs: String, _ rhs: String) -> Bool {
        lhs.utf8.lexicographicallyPrecedes(rhs.utf8)
    }

    private static func opt<T>(_ value: T?, _ encode: (T) -> String) -> String {
        value.map(encode) ?? "-"
    }

    private static func bool(_ value: Bool) -> String { value ? "true" : "false" }

    private static func int<T: BinaryInteger>(_ value: T) -> String { String(value) }

    private static func float(_ value: Double) -> String { String(format: "%.7f", value) }

    /// Store milliseconds. Rounded: every `Date` here was made from whole
    /// milliseconds, so this is the exact inverse.
    private static func ms(_ date: Date) -> String {
        String(Int64((date.timeIntervalSince1970 * 1_000).rounded()))
    }

    private static func bytes(_ value: Data) -> String {
        "x" + value.map { String(format: "%02x", $0) }.joined()
    }

    private static func list(_ items: [String]) -> String { "[" + items.joined(separator: ",") + "]" }

    private static func record(_ fields: [(String, String)]) -> String {
        "{" + fields.map { "\($0.0)=\($0.1)" }.joined(separator: " ") + "}"
    }

    private static func str(_ value: String) -> String {
        var out = "\""
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\\": out += "\\\\"
            case "\"": out += "\\\""
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            case _ where scalar.value < 0x20: out += "\\u{" + String(scalar.value, radix: 16) + "}"
            default: out.unicodeScalars.append(scalar)
            }
        }
        return out + "\""
    }

    private static func systemRole(_ value: MobileStoredSystemRole) -> String {
        switch value {
        case .companionRadio: "companionradio"
        }
    }

    private static func channelKind(_ value: StoredChannelKind) -> String {
        switch value {
        case .builtin: "builtin"
        case .named: "named"
        case .privateKey: "privatekey"
        }
    }

    private static func delivery(_ value: MobileStoredChatDeliveryState) -> String {
        switch value {
        case .pending: "pending"
        case .sent: "sent"
        case .acknowledged: "acknowledged"
        case .failed: "failed"
        case .undelivered: "undelivered"
        }
    }

    private static func signature(_ value: MeshIdentitySignatureState) -> String {
        switch value {
        case .unsigned: "unsigned"
        case .valid: "valid"
        case .invalid: "invalid"
        }
    }
}
