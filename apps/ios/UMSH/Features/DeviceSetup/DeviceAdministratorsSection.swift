import SwiftUI
import UMSHMobileCore

/// One entry of a device's administrator list.
///
/// A device reports keys, not names: what the list means to a person is
/// whatever this phone can put to those bytes — itself, a node it has
/// saved, or nothing at all.
struct DeviceAdministrator: Identifiable, Hashable {
    let publicKey: Data
    /// The node these bytes name, or nil when they are not a node key.
    /// A device should never report anything else; nothing here has to
    /// trust that it does not.
    let identity: MeshPublicIdentity?
    /// This phone itself, which is the entry that matters most and the one
    /// a person is least able to recognize by address.
    let isThisPhone: Bool

    var id: Data { publicKey }

    init(publicKey: Data, isThisPhone: Bool) {
        self.publicKey = publicKey
        self.isThisPhone = isThisPhone
        identity = (try? inspectPublicIdentityBytes(publicKey: publicKey)).map {
            MeshPublicIdentity(
                canonicalAddress: $0.canonicalAddress,
                hint: MeshNodeHint(bytes: $0.hint.bytes, text: $0.hint.text)
            )
        }
    }

    /// What to call this entry, given the nodes the phone has saved.
    func label(among peers: [PeerSummary]) -> String {
        if isThisPhone { return "This phone" }
        guard let identity else { return "Unrecognized key" }
        let saved = peers.first {
            $0.identity.canonicalAddress == identity.canonicalAddress
        }
        return saved?.displayName ?? identity.hint.text
    }
}

/// Who may configure this device from a distance.
///
/// The list is the device's own, and it is the only thing standing between
/// a node on a mast and a node nobody can change: a device answers a
/// management request from a node it lists, and answers nothing at all to
/// one it does not. That silence is why the list is edited here, while the
/// device is in reach, rather than discovered later.
struct DeviceAdministratorsSection: View {
    let administrators: [DeviceAdministrator]
    /// Whether this phone is on the list, as a switch because it is the
    /// entry an operator actually decides.
    @Binding var phoneAdministers: Bool
    /// False on a phone whose own node key is unknown, which leaves the
    /// switch off and unusable rather than lying about what it would do.
    let phoneKeyKnown: Bool
    let isFull: Bool
    /// Nodes this phone has saved, to name entries and to add from.
    let knownPeers: [PeerSummary]
    let add: (Data) -> Void
    let remove: (DeviceAdministrator) -> Void

    var body: some View {
        Section {
            Toggle("This phone", isOn: $phoneAdministers)
                .disabled(!phoneKeyKnown || (isFull && !phoneAdministers))

            ForEach(administrators.filter { !$0.isThisPhone }) { administrator in
                LabeledContent(administrator.label(among: knownPeers)) {
                    Button("Remove") { remove(administrator) }
                }
            }

            if !addable.isEmpty {
                Menu {
                    ForEach(addable) { peer in
                        Button(peer.displayName) { add(peer.publicKey) }
                    }
                } label: {
                    Label("Add a Node", systemImage: "plus")
                }
                .disabled(isFull)
            }
        } header: {
            Text("Administrators")
        } footer: {
            Text(footer)
        }
    }

    /// Saved nodes not already listed, and only those whose key this phone
    /// can produce. Everything about administration is by public key, so a
    /// node known by address alone cannot be added.
    private var addable: [AddableNode] {
        let listed = Set(administrators.map(\.publicKey))
        return knownPeers.compactMap { peer in
            guard let key = try? publicIdentityBytes(
                address: peer.identity.canonicalAddress
            ), !listed.contains(key) else { return nil }
            return AddableNode(id: peer.identity.canonicalAddress, displayName: peer.displayName, publicKey: key)
        }
    }

    private struct AddableNode: Identifiable {
        let id: String
        let displayName: String
        let publicKey: Data
    }

    private var footer: String {
        var footer = """
            Nodes listed here can read and change this device's settings over \
            the mesh. It ignores everyone else, silently.
            """
        if !phoneKeyKnown {
            footer += " This phone's own node identity is not available, so it cannot list itself."
        } else if !phoneAdministers {
            footer += " Without this phone on the list, its settings can only be changed from here, over Bluetooth."
        }
        if isFull {
            footer += " The list is full (\(deviceAdminCapacity) of \(deviceAdminCapacity)) — remove one to add another."
        }
        return footer
    }
}
