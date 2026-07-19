import SwiftUI

struct NetworkView: View {
    @Binding var radioSnapshot: RadioSnapshot
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
            case .list:
                if let radioIdentity = radioSnapshot.deviceIdentity {
                    List {
                        Section("Saved radio") {
                            NavigationLink {
                                PeerDetailView(snapshot: $radioSnapshot)
                            } label: {
                                HStack(spacing: 12) {
                                    PeerAvatar(hint: radioIdentity.hint)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(radioSnapshot.name ?? "Companion radio")
                                        Text("Companion radio identity · \(radioIdentity.hint.text)")
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                    }
                                }
                            }
                        }

                        Section {
                            Button("Discover peers") {}
                        } footer: {
                            Text("Discovery is bounded and may not find every nearby node.")
                        }
                    }
                    .listStyle(.insetGrouped)
                } else {
                    ContentUnavailableView {
                        Label("No observed nodes", systemImage: "point.3.connected.trianglepath.dotted")
                    } description: {
                        Text("Start a bounded discovery session to observe identity-bearing traffic.")
                    } actions: {
                        Button("Discover peers") {}
                            .buttonStyle(.borderedProminent)
                    }
                }
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
}

struct PeerDetailView: View {
    @Binding var snapshot: RadioSnapshot

    var body: some View {
        Group {
            if let identity = snapshot.deviceIdentity {
                List {
                    Section {
                        HStack(spacing: 16) {
                            PeerAvatar(hint: identity.hint, diameter: 64)
                            VStack(alignment: .leading) {
                                Text(snapshot.name ?? "Companion radio")
                                    .font(.title2.bold())
                                Text("Companion radio identity")
                                    .foregroundStyle(.secondary)
                            }
                        }
                        LabeledContent("Type", value: "Companion radio identity")
                        LabeledContent("Node hint", value: identity.hint.text)
                    }

                    Section("Identity") {
                        CanonicalAddressView(address: identity.canonicalAddress)
                    }

                    Section {
                        Text("This peer is managed by the connected radio and cannot be removed separately.")
                            .foregroundStyle(.secondary)
                    }
                }
            } else {
                ContentUnavailableView(
                    "Radio identity unavailable",
                    systemImage: "antenna.radiowaves.left.and.right.slash",
                    description: Text("Connect a companion radio to inspect its identity.")
                )
            }
        }
        .navigationTitle(snapshot.name ?? "Companion radio")
    }
}

private enum NetworkPresentation: Hashable {
    case list
    case map
}
