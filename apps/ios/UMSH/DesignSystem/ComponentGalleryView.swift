#if DEBUG
import SwiftUI

/// Static fixtures only: opening this gallery starts no service and performs
/// no reads or writes. The same examples can be previewed without an app runtime.
struct ComponentGalleryView: View {
    enum Page: String, CaseIterable, Identifiable {
        case peers = "Peers", radios = "Radios", headers = "Headers", fields = "Fields"
        var id: Self { self }
    }

    @State private var page: Page = .peers
    @State private var largeText = false
    @State private var dark = false

    var body: some View {
        List {
            Section("Preview") {
                Picker("Components", selection: $page) {
                    ForEach(Page.allCases) { Text($0.rawValue).tag($0) }
                }
                Toggle("Accessibility text", isOn: $largeText)
                Toggle("Dark appearance", isOn: $dark)
                NavigationLink("Map card on material") {
                    MapCardGalleryExample()
                        .dynamicTypeSize(largeText ? .accessibility3 : .large)
                }
            }
            ComponentGalleryExamples(page: page)
                .dynamicTypeSize(largeText ? .accessibility3 : .large)
        }
        .navigationTitle("Component Gallery")
        .preferredColorScheme(dark ? .dark : .light)
    }
}

struct ComponentGalleryExamples: View {
    let page: ComponentGalleryView.Page
    @State private var frequency = "917500"
    @State private var name = "Ridge relay"

    static let hint = MeshNodeHint(bytes: Data([0xA1, 0xB2, 0x03]), text: "BtC5")
    static let channel = ChannelSummary(
        id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
        kind: .privateKey, canonicalName: nil, name: "Trail Crew", alias: nil,
        channelIDHex: "0a3c", tint: Data([0x3A, 0x8F, 0xD2]), regionCode: nil,
        maxFloodHops: nil, joinedPhone: true, joinedDevice: false,
        notificationsEnabled: false, joinedAt: nil
    )

    var body: some View {
        switch page {
        case .peers: peerExamples
        case .radios: radioExamples
        case .headers: headerExamples
        case .fields: fieldExamples
        }
    }

    private var peerExamples: some View {
        Group {
            Section("Peer rows") {
                PeerRow(hint: Self.hint, title: "Ridge relay", subtitle: "Saved · BtC5", showsFavoriteStar: true)
                PeerRow(hint: Self.hint, title: "North Ridge Search and Rescue Operations", subtitle: "Heard 5m ago · BtC5")
                PeerRow(hint: nil, title: "Unrecognized key")
                PeerRow(hint: Self.hint, title: "Hilltop", subtitle: "Position reported by a router") {
                    Image(systemName: "antenna.radiowaves.left.and.right")
                        .font(.caption2).foregroundStyle(.secondary)
                        .accessibilityLabel("Position reported by a router")
                } trailing: {
                    Text("1.2 km").monospacedDigit()
                }
                PeerRow(hint: Self.hint, title: "Unverified location", subtitle: "Heard 2h ago") {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.caption2).foregroundStyle(.orange)
                        .accessibilityLabel("Location unverified")
                } trailing: {
                    Text("12.8 km").monospacedDigit()
                }
            }
            Section("Compact rows") {
                PeerRow(hint: Self.hint, title: "Sleeping relay", subtitle: "−104 dBm · 8h ago\nUS · Position reported", size: .compact, isStale: true)
                PeerRow(hint: Self.hint, title: "This phone", size: .compact)
            }
            Section("Channels") {
                ChannelRow(channel: Self.channel)
                ChannelIdentityRow(channel: Self.channel) { Text("Private · 0a3c") }
            }
        }
    }

    private var radioExamples: some View {
        Section("Radio discovery") {
            RadioDiscoveryRow(radio: radio("Trail radio", rssi: -65), fallbackName: "Unnamed radio", badge: "Saved")
            RadioDiscoveryRow(radio: radio("North Ridge Search and Rescue Radio", rssi: -80), fallbackName: "Unnamed device", badge: "This phone's radio")
            RadioDiscoveryRow(radio: radio(nil, rssi: 127), fallbackName: "Unnamed device")
            RadioDiscoveryRow(radio: radio("Previous radio", rssi: -95, migration: true), fallbackName: "Unnamed radio", badge: "Saved")
            RadioDiscoveryRow(radio: radio("Connecting radio", rssi: -70), fallbackName: "Unnamed radio", isBusy: true)
        }
    }

    private var headerExamples: some View {
        Group {
            Section("Information") {
                IdentityHeader { diameter in
                    PeerAvatar(hint: Self.hint, diameter: diameter)
                } content: {
                    IdentityHeaderText(title: "North Ridge Search and Rescue", subtitle: "Companion radio identity")
                }
                IdentityHeader { diameter in
                    ChannelAvatar(channel: Self.channel, size: diameter)
                } content: {
                    IdentityHeaderText(title: Self.channel.title, subtitle: Self.channel.kindLabel)
                }
            }
            Section("Editable profile") {
                IdentityHeader(style: .profile) { diameter in
                    PeerAvatar(hint: Self.hint, diameter: diameter)
                } content: {
                    VStack(alignment: .leading) {
                        TextField("Name", text: $name).font(.title2.bold())
                        Text("Repeater").foregroundStyle(.secondary)
                    }
                }
            }
            Section("Onboarding") {
                IdentityHeader(style: .hero) { diameter in
                    PeerAvatar(hint: Self.hint, diameter: diameter)
                } content: {
                    VStack(spacing: 8) {
                        Text("Welcome to UMSH").font(.title2.bold())
                        Text("This phone has an identity of its own.").foregroundStyle(.secondary)
                    }
                    .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity)
            }
        }
    }

    private var fieldExamples: some View {
        Group {
            Section {
                RemoteNumberField("Frequency", unit: "kHz", text: $frequency, isKnown: true)
                RemoteNumberField("Transmit power", unit: "dBm", text: .constant("30"), isKnown: true, signed: true, problem: "The device rejected this value.")
                RemoteNumberField("Bandwidth", unit: "Hz", text: .constant(""), isKnown: false)
                RemoteTextField("Name", text: $name, isKnown: true)
                RemoteReadOnlyToggle("Radio enabled", isOn: true)
                RemoteReadOnlyToggle("Bluetooth enabled", isOn: nil)
            } header: {
                Text("Settings")
            } footer: {
                RemoteReadingFooter(asOf: nil, isFresh: false, isBusy: false, subject: "the device")
            }
            Section("Reading states") {
                RemoteReadingFooter(asOf: nil, isFresh: false, isBusy: true, subject: "the device")
                RemoteReadingFooter(asOf: Date(timeIntervalSince1970: 1_790_000_000), isFresh: true, isBusy: false, subject: "the device")
                RemoteReadingFooter(asOf: Date(timeIntervalSince1970: 1_790_000_000), isFresh: false, isBusy: false, subject: "the device")
            }
            Section("Badges") {
                HStack {
                    StatusBadge(title: "Saved")
                    StatusBadge(title: "This phone's radio")
                }
            }
        }
    }

    private func radio(_ name: String?, rssi: Int, migration: Bool = false) -> DiscoveredRadio {
        DiscoveredRadio(id: Self.channel.id, name: name, rssiDBm: rssi, isRemembered: true, requiresMigration: migration)
    }
}

/// Exercise the actual List on the map's material. Plain-background row
/// previews cannot catch foreground-style/vibrancy regressions here.
struct MapCardGalleryExample: View {
    @State private var detent: MapCardDetent = .tall
    @State private var selectedNodeID: MapNodeID?

    var body: some View {
        GeometryReader { geometry in
            ZStack(alignment: .bottom) {
                LinearGradient(
                    colors: [.green.opacity(0.4), .yellow.opacity(0.3)],
                    startPoint: .topLeading, endPoint: .bottomTrailing
                )
                MapBottomCard(
                    detent: $detent, availableHeight: geometry.size.height,
                    peekHeight: 160
                ) {
                    Text("3 nodes").font(.headline)
                } content: {
                    MapNodeListCard(
                        nodes: nodes, selectedNodeID: $selectedNodeID,
                        selfPosition: MapSelfPosition(radioPosition: StagingScenario.radioSnapshot.position),
                        hasAnyLocations: true, isFiltered: false,
                        clearFilters: {}, discoverPeers: {}, openPeersList: {},
                        radioSnapshot: .constant(.idle), conversations: .constant([]),
                        updateDraft: nil, sendMessage: nil
                    )
                }
            }
        }
        .navigationTitle("Map card")
        .navigationBarTitleDisplayMode(.inline)
    }

    private var nodes: [MapNode] {
        let reporter = PeerSummary(
            id: 10,
            identity: MeshPublicIdentity(canonicalAddress: "Gallery reporter", hint: ComponentGalleryExamples.hint),
            alias: "Ridge relay", advertisedName: nil, systemRole: nil, storedRole: .repeater
        )
        return [
            node(1, title: "Ridge relay", isFavorite: true),
            node(2, title: "Old location", locationAge: 28_800),
            node(3, title: "Reported neighbor", reporter: reporter),
        ]
    }

    private func node(
        _ id: Int64, title: String, isFavorite: Bool = false,
        locationAge: TimeInterval = 300, reporter: PeerSummary? = nil
    ) -> MapNode {
        MapNode(
            id: .peer(id), peer: nil, displayName: title,
            hint: ComponentGalleryExamples.hint, isFavorite: isFavorite,
            reportedBy: reporter,
            latitude: 38.91, longitude: -120.1, cellMeters: 38.2,
            reportedAt: Date.now.addingTimeInterval(-locationAge),
            lastHeard: Date.now.addingTimeInterval(-300), isAttributable: true
        )
    }
}

#Preview("Map card on material") {
    NavigationStack { MapCardGalleryExample() }
}

#Preview("Component gallery") {
    NavigationStack { ComponentGalleryView() }
}

#Preview("Peer rows: large text") {
    List { ComponentGalleryExamples(page: .peers) }
        .dynamicTypeSize(.accessibility3)
}
#endif
