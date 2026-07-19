import SwiftUI

struct NetworkView: View {
    @Binding var radioSnapshot: RadioSnapshot
    let peers: [PeerSummary]
    @State private var presentation: NetworkPresentation = .list

    var body: some View {
        VStack(spacing: 0) {
            Picker("Presentation", selection: $presentation) {
                Text("List").tag(NetworkPresentation.list)
                Text("Map").tag(NetworkPresentation.map)
            }
            .pickerStyle(.segmented)
            .padding()

            switch presentation {
            case .list: peerList
            case .map:
                ContentUnavailableView {
                    Label("No reported locations", systemImage: "map")
                } description: {
                    Text("Locations reported by observed nodes will appear here with their precision and age.")
                }
            }
        }
        .navigationTitle("Network")
    }

    @ViewBuilder
    private var peerList: some View {
        if peers.isEmpty {
            ContentUnavailableView {
                Label("No known nodes", systemImage: "point.3.connected.trianglepath.dotted")
            } description: {
                Text("Import a peer or start a bounded discovery session.")
            } actions: {
                Button("Discover peers") {}
                    .buttonStyle(.borderedProminent)
            }
        } else {
            List {
                let radios = peers.filter(\.isCompanionRadio)
                if !radios.isEmpty {
                    Section("Saved radio") {
                        ForEach(radios) { peer in peerLink(peer) }
                    }
                }
                let contacts = peers.filter { !$0.isCompanionRadio && $0.isContact }
                if !contacts.isEmpty {
                    Section("Contacts") {
                        ForEach(contacts) { peer in peerLink(peer) }
                    }
                }
                let recent = peers.filter { !$0.isCompanionRadio && !$0.isContact }
                if !recent.isEmpty {
                    Section("Known nodes") {
                        ForEach(recent) { peer in peerLink(peer) }
                    }
                }
                Section {
                    Button("Discover peers") {}
                } footer: {
                    Text("Discovery is bounded and may not find every nearby node.")
                }
            }
            .listStyle(.insetGrouped)
        }
    }

    private func peerLink(_ peer: PeerSummary) -> some View {
        NavigationLink {
            PeerDetailView(peer: peer, radioSnapshot: $radioSnapshot)
        } label: {
            HStack(spacing: 12) {
                PeerAvatar(hint: peer.identity.hint)
                VStack(alignment: .leading, spacing: 2) {
                    Text(peer.displayName)
                    Text(peer.isCompanionRadio
                         ? "Companion radio identity · \(peer.identity.hint.text)"
                         : peer.identity.hint.text)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}

struct PeerDetailView: View {
    let peer: PeerSummary
    @Binding var radioSnapshot: RadioSnapshot

    var body: some View {
        List {
            Section {
                HStack(spacing: 16) {
                    PeerAvatar(hint: peer.identity.hint, diameter: 64)
                    VStack(alignment: .leading) {
                        Text(peer.displayName).font(.title2.bold())
                        Text(peer.isCompanionRadio ? "Companion radio identity" : "UMSH peer")
                            .foregroundStyle(.secondary)
                    }
                }
                LabeledContent("Type", value: peer.isCompanionRadio ? "Companion radio identity" : "Peer")
                LabeledContent("Node hint", value: peer.identity.hint.text)
            }

            Section("Identity") {
                CanonicalAddressView(address: peer.identity.canonicalAddress)
            }

            if peer.isCompanionRadio {
                Section {
                    Text("This peer is managed by the saved radio and cannot be removed separately.")
                        .foregroundStyle(.secondary)
                    LabeledContent("Radio", value: radioSnapshot.name ?? "Saved companion radio")
                }
            }
        }
        .navigationTitle(peer.displayName)
    }
}

private enum NetworkPresentation: Hashable {
    case list
    case map
}
