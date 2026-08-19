import SwiftUI
import UMSHMobileCore

/// Who this device talks to, and who may change it.
///
/// Two tables of public keys, edited one entry at a time — a device takes an
/// insert or a remove, not a list — and saved once when the operator is
/// done. Both lists apply as they are edited rather than behind an Apply
/// button, because each entry is its own exchange with the device and there
/// is nothing to batch.
struct RemotePeerNodesScreen: View {
    let model: ManageDeviceModel
    let browsing: RemotePeerBrowsing

    private var reading: RemoteCategoryReading? { model.readings[.peerNodes] }

    var body: some View {
        Form {
            peersSection
            if model.card?.supportsAdmin == true {
                administratorsSection
            }
            Section {
                EmptyView()
            } footer: {
                RemoteReadingFooter(reading: reading, isBusy: model.isBusy)
            }
            RemoteProblemSection(model: model)
        }
        .remoteCategoryChrome(model: model, category: .peerNodes, title: "Peer Nodes")
    }

    // MARK: - Peers

    private var peers: [DeviceAdministrator] {
        (reading?.properties.devPeerKeys ?? []).map {
            DeviceAdministrator(publicKey: $0, isThisPhone: $0 == model.phoneNodeKey)
        }
    }

    private var peersSection: some View {
        Section {
            ForEach(peers) { peer in
                row(peer, removable: true) { setPeers(removing: peer.publicKey) }
            }
            if peers.isEmpty {
                Text(reading?.asOf == nil ? "Not read" : "None")
                    .foregroundStyle(.secondary)
            }
            addMenu(listed: Set(peers.map(\.publicKey))) { setPeers(adding: $0) }
        } header: {
            Text("Peers")
        } footer: {
            Text("The device can reach these nodes without this phone in the middle.")
        }
    }

    private func setPeers(adding key: Data? = nil, removing removed: Data? = nil) {
        var desired = Set(peers.map(\.publicKey))
        if let key { desired.insert(key) }
        if let removed { desired.remove(removed) }
        Task { await model.setKeys(desired, administrators: false) }
    }

    // MARK: - Administrators

    private var administrators: [DeviceAdministrator] {
        (reading?.properties.devAdminKeys ?? []).map {
            DeviceAdministrator(publicKey: $0, isThisPhone: $0 == model.phoneNodeKey)
        }
    }

    /// This phone's own entry is never removable here.
    ///
    /// Taking it off would be the last request this device answered, and the
    /// save behind it would arrive from a node it no longer lists. Same for
    /// emptying the list: a device with no administrators can only be
    /// changed over Bluetooth, by someone standing next to it.
    private var administratorsSection: some View {
        Section {
            ForEach(administrators) { administrator in
                // This phone's own entry offers no Remove, and neither does
                // the last one standing; the footer says why.
                row(
                    administrator,
                    removable: !administrator.isThisPhone && administrators.count > 1
                ) { setAdministrators(removing: administrator.publicKey) }
            }
            if administrators.isEmpty {
                Text(reading?.asOf == nil ? "Not read" : "None")
                    .foregroundStyle(.secondary)
            }
            addMenu(listed: Set(administrators.map(\.publicKey))) {
                setAdministrators(adding: $0)
            }
        } header: {
            Text("Administrators")
        } footer: {
            Text(footer)
        }
    }

    private var footer: String {
        var footer = "These nodes can read and change this device's settings over the mesh."
        if administrators.contains(where: \.isThisPhone) {
            footer += " This phone cannot remove itself — connect over Bluetooth to do that."
        }
        return footer
    }

    private func setAdministrators(adding key: Data? = nil, removing removed: Data? = nil) {
        var desired = Set(administrators.map(\.publicKey))
        if let key { desired.insert(key) }
        if let removed, removed != model.phoneNodeKey, desired.count > 1 {
            desired.remove(removed)
        }
        Task { await model.setKeys(desired, administrators: true) }
    }

    // MARK: - Rows

    /// One key a device holds, as a node.
    ///
    /// Every key that reads as a node opens that node's page, whether or not
    /// this phone has it saved — an unsaved one arrives there as itself, and
    /// saving it is what that page's own action is for. Removal is a swipe
    /// rather than a button on the row, so tapping a node does what tapping
    /// a node does everywhere else.
    @ViewBuilder
    private func row(
        _ entry: DeviceAdministrator,
        removable: Bool,
        remove: @escaping () -> Void
    ) -> some View {
        Group {
            if let identity = entry.identity, !entry.isThisPhone {
                let saved = browsing.knownPeers.first {
                    $0.identity.canonicalAddress == identity.canonicalAddress
                }
                NavigationLink {
                    browsing.open(saved ?? Self.unsavedNode(identity))
                } label: {
                    if let saved {
                        PeerRow(peer: saved, diameter: 32)
                    } else {
                        PeerRow(hint: identity.hint, title: "Unsaved node", diameter: 32)
                    }
                }
            } else {
                // This phone is not a node to go and look at, and bytes that
                // do not read as a key have no page behind them.
                PeerRow(
                    hint: entry.identity?.hint,
                    title: entry.isThisPhone ? "This phone" : "Unrecognized key",
                    diameter: 32
                )
            }
        }
        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
            if removable {
                Button(role: .destructive, action: remove) {
                    Label("Remove", systemImage: "trash")
                }
            }
        }
    }

    /// A node this phone holds no record of, presented as an ordinary node
    /// so it opens the same page. Nothing is stored behind it, which is
    /// exactly what that page's save action is for.
    private static func unsavedNode(_ identity: MeshPublicIdentity) -> PeerSummary {
        PeerSummary(
            id: 0,
            identity: identity,
            alias: nil,
            advertisedName: nil,
            systemRole: nil,
            storedRole: .unknown,
            isSaved: false
        )
    }

    // MARK: - Adding

    /// Saved nodes not already listed, and only those whose key this phone
    /// can produce. Everything here is by public key, so a node known by
    /// address alone cannot be added.
    @ViewBuilder
    private func addMenu(listed: Set<Data>, add: @escaping (Data) -> Void) -> some View {
        let addable = browsing.knownPeers.compactMap { peer -> (PeerSummary, Data)? in
            guard let key = try? publicIdentityBytes(
                address: peer.identity.canonicalAddress
            ), !listed.contains(key) else { return nil }
            return (peer, key)
        }
        if !addable.isEmpty {
            Menu {
                ForEach(addable, id: \.0.id) { peer, key in
                    Button(peer.displayName) { add(key) }
                }
            } label: {
                Label("Add a Node", systemImage: "plus")
            }
        }
    }
}
