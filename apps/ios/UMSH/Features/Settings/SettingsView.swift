import CoreLocation
import SwiftUI
import UMSHMobileCore

struct SettingsView: View {
    let identity: LocalIdentitySnapshot?
    let identityError: IdentityVaultError?
    let isLoadingIdentity: Bool
    let createIdentity: () async -> Void
    var advertisedName: String = ""
    var saveAdvertisedName: (String) async -> Void = { _ in }
    var advertiseIdentity: () async -> String? = { nil }
    var identityShareURI: (() async -> String)? = nil
    /// Whether this phone answers nearby nodes' identity requests, and the
    /// action that changes it. Absent when no mesh session can exist.
    var phoneDiscoverable: Bool = true
    var setPhoneDiscoverable: ((Bool) async -> Void)? = nil
    @Binding var radioSnapshot: RadioSnapshot
    let connectRadio: () async -> Void
    let reconnectRadio: () async -> Void
    let claimRadio: () async -> Void
    let refreshRadio: () async -> Void
    let disconnectRadio: () async -> Void
    var forgetRadio: () async -> Void = {}
    var factoryResetRadio: () async throws -> Void = {}
    let discoverRadios: () async -> AsyncStream<[DiscoveredRadio]>
    let selectRadio: (UUID) async throws -> Void
    let stopDiscovery: () async -> Void
    /// Records a device met during setup as an ordinary peer. Absent when
    /// there is no identity or store to record it against.
    var saveDevicePeer: ((MeshPublicIdentity, String?, PeerRole) async -> Bool)? = nil
    /// Whether a node address is already in this phone's Peers list.
    var isPeerSaved: (String) -> Bool = { _ in false }
    /// Handed to every peer sheet reachable from Settings so those sheets
    /// match the ones opened from Peers.
    var peerActions: PeerActions = .unavailable
    /// The app's conversation list plus messaging closures, threaded to the
    /// radio identity's peer sheet so its "Message" button opens a working
    /// transcript instead of a blank destination.
    var conversations: Binding<[DirectConversationSummary]> = .constant([])
    var updateDraft: ((Int64, String) async -> Void)? = nil
    var sendMessage: ((DirectConversationSummary, String) async -> MessageSendResult)? = nil
    var messageActions: ChatMessageActions = .unavailable
    var channels: [ChannelSummary] = []
    var unknownDeviceChannels: [UnknownDeviceChannel] = []
    var channelActions: ChannelActions = .unavailable

    /// Fills a conversation with generated messages, for exercising the
    /// transcript at a size no test account reaches by hand. Only supplied by
    /// debug builds; the control that calls it only exists there too.
    var seedMessages: ((String, Int) async -> Void)? = nil

    @Environment(\.regionService) private var regionService
    @State private var showsDeviceSetup = false
    @State private var isSeeding = false
    #if DEBUG
    /// Read straight from storage, as the announcement schedules above are:
    /// `UMSHApp` reads the same key to decide which store and radio to build,
    /// so a closure round trip would only add a way for the two to disagree.
    @AppStorage("staging.enabled") private var stagingEnabled = false
    @State private var stagingResetFailed = false
    @AppStorage("debug.radioTcp.enabled") private var tcpRadioEnabled = false
    @AppStorage("debug.radioTcp.endpoint") private var tcpRadioEndpoint = "127.0.0.1:9000"
    #endif

    /// What this build knows about the world's routing regions.
    ///
    /// Read-only, and stated rather than acted on: the database ships with
    /// the app, is never consulted over the network, and the only thing an
    /// operator can do about it is know which release they are suggesting
    /// regions from.
    @ViewBuilder
    private var regionDatabaseSection: some View {
        Section {
            if let version = regionService?.datasetVersion {
                LabeledContent("Data release", value: version)
                if let count = regionService?.regionCount {
                    LabeledContent("Regions", value: count.formatted())
                }
            } else if let problem = regionService?.unavailableMessage {
                Text(problem).foregroundStyle(.secondary)
            } else {
                Text("Opening…").foregroundStyle(.secondary)
            }
        } header: {
            Text("Region database")
        } footer: {
            Text("Used to suggest routing regions for a device from where it is. Lookups run on this phone and are never sent anywhere.")
        }
    }

    private func seedConversation(_ count: Int) async {
        guard let seedMessages, let first = conversations.wrappedValue.first else { return }
        await seedMessages(first.conversationAddress, count)
    }

    var body: some View {
        List {
            Section("Identity") {
                if let identity {
                    NavigationLink {
                        IdentityDetailView(
                            identity: identity,
                            advertisedName: advertisedName,
                            saveAdvertisedName: saveAdvertisedName,
                            advertiseIdentity: advertiseIdentity,
                            identityShareURI: identityShareURI,
                            phoneDiscoverable: phoneDiscoverable,
                            setPhoneDiscoverable: setPhoneDiscoverable
                        )
                    } label: {
                        HStack(spacing: 12) {
                            PeerAvatar(hint: identity.publicIdentity.hint)
                            VStack(alignment: .leading) {
                                Text("Your identity")
                                Text(identity.publicIdentity.hint.text)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                } else if isLoadingIdentity {
                    HStack {
                        ProgressView()
                        Text("Checking protected identity")
                    }
                } else {
                    Button {
                        Task { await createIdentity() }
                    } label: {
                        Label("Create identity", systemImage: "person.crop.circle.badge.plus")
                    }
                }

                // Channel membership belongs to the identity: the keys are
                // held by it, and switching identities would change the set.
                if identity != nil {
                    NavigationLink {
                        ChannelsView(
                            channels: channels,
                            unknownDeviceChannels: unknownDeviceChannels,
                            radioSnapshot: radioSnapshot,
                            actions: channelActions
                        )
                    } label: {
                        LabeledContent("Channels") {
                            Text("\(channels.filter(\.isJoined).count)")
                        }
                    }
                }

                if identityError != nil {
                    Text("Identity is unavailable while protected data is locked or storage cannot be accessed.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Section("Radio") {
                NavigationLink("Companion radio") {
                    RadioDetailView(
                        snapshot: $radioSnapshot,
                        connect: connectRadio,
                        reconnect: reconnectRadio,
                        claim: claimRadio,
                        refresh: refreshRadio,
                        disconnect: disconnectRadio,
                        forget: forgetRadio,
                        factoryReset: factoryResetRadio,
                        discoverRadios: discoverRadios,
                        selectRadio: selectRadio,
                        stopDiscovery: stopDiscovery,
                        peerActions: peerActions,
                        conversations: conversations,
                        updateDraft: updateDraft,
                        sendMessage: sendMessage,
                        messageActions: messageActions
                    )
                }
            }

            Section {
                Button {
                    showsDeviceSetup = true
                } label: {
                    Label("Set up a device…", systemImage: "badge.plus.radiowaves.right")
                }
            } header: {
                Text("Devices")
            } footer: {
                Text("Configure any nearby UMSH device — a repeater or a tracker — without disturbing this phone's own connection.")
            }

            regionDatabaseSection

            #if DEBUG
            Section {
                Button("Terminate this app", role: .destructive) {
                    // SIGKILL rather than exit(0): the app stays eligible for
                    // CoreBluetooth to relaunch it, which a force-quit from
                    // the app switcher deliberately does not. That makes this
                    // the only way to watch a background relaunch stand the
                    // pipeline up without a scene.
                    kill(getpid(), SIGKILL)
                }
            } header: {
                Text("Background relaunch")
            } footer: {
                Text("Kills the app the way the system does when it reclaims memory, leaving the saved radio's connection armed. Power the radio on, or have another node send a message, and iOS should relaunch this app with no screen at all — far enough to store the message and raise a notification. Debug builds only.")
            }

            Section {
                Toggle("Radio over TCP", isOn: $tcpRadioEnabled)
                TextField("127.0.0.1:9000", text: $tcpRadioEndpoint)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                    .font(.body.monospaced())
                if TcpEndpoint(tcpRadioEndpoint) == nil {
                    Text("Give the bridge as host:port.")
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            } header: {
                Text("Bridged radio")
            } footer: {
                Text("Reaches a companion radio over a socket instead of Bluetooth, which is the only way a simulator build can talk to real hardware. Bridge the radio's port with socat, then point this at it. Debug builds only.")
            }

            Section {
                Toggle("Staging mode", isOn: $stagingEnabled)
                Button("Reset staged data", role: .destructive) {
                    // Leaving staging hands the app back to the real store, so
                    // the emptied database is one nothing is about to write to
                    // again — and the next time it is switched on, bootstrap
                    // seeds the staged mesh afresh against that day's clock.
                    stagingEnabled = false
                    Task {
                        do {
                            try await SQLiteApplicationStore.eraseStagingStore()
                            stagingResetFailed = false
                        } catch {
                            stagingResetFailed = true
                        }
                    }
                }
                if stagingResetFailed {
                    Text("The staged database could not be removed.")
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            } header: {
                Text("Staging")
            } footer: {
                Text("Replaces this phone's data with a fabricated trail-crew mesh — peers, conversations, reactions and map nodes — and reports a companion radio that is attached, charged and holding a fix. For marketing screenshots. Staged content lives in its own database and never touches your real one. Debug builds only.")
            }

            Section {
                Button("Seed 2000 Messages") {
                    isSeeding = true
                    Task {
                        await seedConversation(2_000)
                        isSeeding = false
                    }
                }
                .disabled(isSeeding || conversations.wrappedValue.isEmpty)
                if isSeeding {
                    HStack(spacing: 8) {
                        ProgressView()
                        Text("Seeding…").foregroundStyle(.secondary)
                    }
                }
            } header: {
                Text("Developer")
            } footer: {
                Text("Fills the first conversation with generated messages, for checking how the transcript behaves at size. Debug builds only.")
            }
            #endif
        }
        .navigationTitle("Settings")
        .sheet(isPresented: $showsDeviceSetup) {
            DeviceSetupFlowView(
                hostIdentity: identity?.publicIdentity,
                companionIdentifier: radioSnapshot.localIdentifier,
                companionName: radioSnapshot.name,
                companionProfile: CompanionRadioProfile(
                    radioSnapshot.provisioning,
                    name: radioSnapshot.name
                ),
                saveDevicePeer: saveDevicePeer,
                isPeerSaved: isPeerSaved,
                peerActions: peerActions
            )
        }
    }
}

struct IdentityDetailView: View {
    let identity: LocalIdentitySnapshot
    var advertisedName: String = ""
    var saveAdvertisedName: (String) async -> Void = { _ in }
    var advertiseIdentity: () async -> String? = { nil }
    var identityShareURI: (() async -> String)? = nil
    var phoneDiscoverable: Bool = true
    var setPhoneDiscoverable: ((Bool) async -> Void)? = nil

    @State private var shareURI = ""
    @State private var nameDraft = ""
    @State private var isAdvertising = false
    @State private var advertiseFeedback: AdvertiseFeedback?
    @State private var discoverableDraft = true
    /// Read straight from storage here rather than passed in: these drive
    /// the schedules in `AppRootView`, which reads the same keys, so a
    /// closure round trip would only add a way for the two to disagree.
    @AppStorage("phone.advertIntervalSeconds") private var phoneAdvertInterval = 0
    @AppStorage("phone.beaconIntervalSeconds") private var phoneBeaconInterval = 0
    @AppStorage("phone.shareLocation") private var phoneSharesLocation = false
    @AppStorage("phone.locationPrecision") private var phoneLocationPrecision = 5

    var body: some View {
        List {
            Section {
                HStack(spacing: 16) {
                    PeerAvatar(hint: identity.publicIdentity.hint, diameter: 64)
                    VStack(alignment: .leading) {
                        Text("Your identity")
                            .font(.title2.bold())
                        Text("Stored on this device")
                            .foregroundStyle(.secondary)
                    }
                }
            }

            Section {
                IdentityShareView(
                    uri: shareURI.isEmpty ? identity.publicIdentity.nodeURI : shareURI
                )
                CanonicalAddressView(address: identity.publicIdentity.canonicalAddress)
            } header: {
                Text("Identity")
            } footer: {
                Text(shareURI.count > identity.publicIdentity.nodeURI.count
                     ? "The QR code carries your public key plus your signed identity details."
                     : "The QR code carries your public key. Connect the companion radio to include signed identity details.")
            }

            Section {
                TextField("Name (optional)", text: $nameDraft)
                    .textInputAutocapitalization(.words)
                    .onSubmit { Task { await commitName() } }
                Button {
                    Task { await advertise() }
                } label: {
                    Label(isAdvertising ? "Advertising…" : "Advertise Identity",
                          systemImage: "dot.radiowaves.left.and.right")
                }
                .disabled(isAdvertising)
                if let advertiseFeedback {
                    Label(advertiseFeedback.message, systemImage: advertiseFeedback.symbol)
                        .font(.caption)
                        .foregroundStyle(advertiseFeedback.isSuccess ? .green : .red)
                }
                if setPhoneDiscoverable != nil {
                    Toggle("Discoverable", isOn: Binding(
                        get: { discoverableDraft },
                        set: { newValue in
                            discoverableDraft = newValue
                            Task { await setPhoneDiscoverable?(newValue) }
                        }
                    ))
                }
            } header: {
                Text("Advertised identity")
            } footer: {
                Text(advertisedIdentityFooter)
            }

            Section {
                Picker("Beacon", selection: $phoneBeaconInterval) {
                    ForEach(beaconIntervalChoices, id: \.self) { seconds in
                        Text(formattedAnnouncementInterval(seconds)).tag(Int(seconds))
                    }
                }
                Picker("Identity", selection: $phoneAdvertInterval) {
                    ForEach(advertisementIntervalChoices, id: \.self) { seconds in
                        Text(formattedAnnouncementInterval(seconds)).tag(Int(seconds))
                    }
                }
            } header: {
                Text("Announce on a schedule")
            } footer: {
                Text("Both run only while UMSH is open — iOS gives a suspended app no way to keep talking to the mesh. A beacon publishes the path back to this phone; an identity announcement carries your name and reaches only nodes that can hear you directly. Each interval is a minimum: periods run a little longer at random, so phones on the same schedule do not all transmit at once.")
            }

            Section {
                Toggle("Share location in identity", isOn: $phoneSharesLocation)
                if phoneSharesLocation {
                    Picker("Shared precision", selection: $phoneLocationPrecision) {
                        ForEach(1...7, id: \.self) { precision in
                            Text(precisionLabel(UInt8(precision))).tag(precision)
                        }
                    }
                    if locationAccessDenied {
                        Label(
                            "Location access for UMSH is off in iOS Settings, so nothing is shared.",
                            systemImage: "location.slash"
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                }
            } header: {
                Text("Location")
            } footer: {
                Text(locationFooter)
            }

            Section("Storage") {
                LabeledContent("Private key", value: "Device-only Keychain")
                Text("Private key bytes are never displayed, copied, synchronized, or included in diagnostics.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("Your identity")
        .task {
            nameDraft = advertisedName
            discoverableDraft = phoneDiscoverable
            await refreshShareURI()
        }
    }

    private var advertisedIdentityFooter: String {
        var footer = "Advertising broadcasts your public key, name, and capabilities to every nearby node, signed by your identity."
        if setPhoneDiscoverable != nil {
            footer += discoverableDraft
                ? " While discoverable, this phone also answers nearby nodes that ask it to identify itself."
                : " This phone ignores nearby nodes that ask it to identify itself."
        }
        return footer
    }

    private var locationFooter: String {
        guard phoneSharesLocation else {
            return "Your identity says nothing about where you are."
        }
        return "Identity announcements and replies name a \(precisionLabel(UInt8(clamping: phoneLocationPrecision))) area you are inside — never a more precise position than that. The shareable QR code never carries it, and your location is read only while UMSH is open."
    }

    /// Live enough for a footer: re-read on every body evaluation, so it
    /// catches up when the user returns from iOS Settings.
    private var locationAccessDenied: Bool {
        let status = CLLocationManager().authorizationStatus
        return status == .denied || status == .restricted
    }

    private func precisionLabel(_ precision: UInt8) -> String {
        LocationPresentation.precisionLabel(precisionBytes: precision)
    }

    private func commitName() async {
        await saveAdvertisedName(nameDraft)
        await refreshShareURI()
    }

    private func advertise() async {
        guard !isAdvertising else { return }
        isAdvertising = true
        defer { isAdvertising = false }
        // Any pending name edit rides along with the advertisement.
        await saveAdvertisedName(nameDraft)
        if let message = await advertiseIdentity() {
            advertiseFeedback = AdvertiseFeedback(message: message, isSuccess: false)
        } else {
            advertiseFeedback = AdvertiseFeedback(
                message: "Advertisement broadcast",
                isSuccess: true
            )
            await refreshShareURI()
        }
    }

    private func refreshShareURI() async {
        if let identityShareURI {
            shareURI = await identityShareURI()
        }
    }
}

private struct AdvertiseFeedback {
    let message: String
    let isSuccess: Bool

    var symbol: String {
        isSuccess ? "checkmark.circle.fill" : "exclamationmark.triangle.fill"
    }
}

struct RadioDetailView: View {
    @Binding var snapshot: RadioSnapshot
    let connect: () async -> Void
    let reconnect: () async -> Void
    let claim: () async -> Void
    let refresh: () async -> Void
    let disconnect: () async -> Void
    var forget: () async -> Void = {}
    var factoryReset: () async throws -> Void = {}
    let discoverRadios: () async -> AsyncStream<[DiscoveredRadio]>
    let selectRadio: (UUID) async throws -> Void
    let stopDiscovery: () async -> Void
    /// So the radio's own node identity opens the same peer sheet as any
    /// other node.
    var peerActions: PeerActions = .unavailable
    /// Conversation list plus messaging closures for that peer sheet, so
    /// "Message" there opens a working transcript.
    var conversations: Binding<[DirectConversationSummary]> = .constant([])
    var updateDraft: ((Int64, String) async -> Void)? = nil
    var sendMessage: ((DirectConversationSummary, String) async -> MessageSendResult)? = nil
    var messageActions: ChatMessageActions = .unavailable
    @Environment(\.dismiss) private var dismiss
    @State private var confirmsHostReplacement = false
    @State private var confirmsForget = false
    @State private var confirmsFactoryReset = false
    @State private var factoryResetProblem: String?
    @State private var showsRadioPicker = false

    var body: some View {
        List {
            Section("Connection") {
                LabeledContent("State", value: snapshot.linkState.accessibilityLabel)
                if let name = snapshot.name {
                    LabeledContent("Radio", value: name)
                }
                if let identifier = snapshot.localIdentifier {
                    // Not "Bluetooth ID": a bridged radio has one of
                    // these too, and it never came from Bluetooth.
                    LabeledContent("Radio ID") {
                        Text(identifier.uuidString)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                    }
                }
                if snapshot.hostState != .unknown {
                    LabeledContent("Host identity", value: snapshot.hostState.label)
                }
                connectionControl
                if let problem = snapshot.problemDescription {
                    Label(problem, systemImage: "exclamationmark.circle")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if snapshot.linkState == .reconnecting {
                    Text("Trying only the saved companion radio. Other nearby radios will not be selected.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if snapshot.linkState == .attaching {
                    Text("Bluetooth transport is attached. Waiting to start radio synchronization.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if snapshot.linkState == .synchronizing {
                    Text(snapshot.hostState == .unsupported
                         ? "Reading the transparent radio's PHY state. This radio does not provide host filtering or offline assistance."
                         : "The phone identity matches this radio. Reading its authoritative provisioning state before enabling traffic.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if snapshot.linkState == .attached {
                    Text("Radio state inspection is complete and mesh traffic is enabled.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if snapshot.linkState == .configuring {
                    Text("Applying radio settings, verifying the echoed values, and saving them on the radio.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if snapshot.hostState == .localIdentityUnavailable {
                    Text("Create or unlock the phone identity before configuring this radio.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if snapshot.hostState == .belongsToAnotherIdentity {
                    Text("This radio belongs to another host. Replacing it clears that host's keys, filters, and queued traffic.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Section("Configuration") {
                // The same management sheet every device gets, over this
                // radio's own link: reads refresh on sight, and the radio's
                // unsolicited announcements keep the screens current.
                if let deviceIdentity = snapshot.deviceIdentity,
                   let manageDevice = peerActions.manageDevice,
                   snapshot.provisioning != nil, canEditConfiguration {
                    let peer = companionPeer(deviceIdentity)
                    NavigationLink {
                        ManageDeviceScreen(
                            peer: peer,
                            management: manageDevice(peer),
                            browsing: companionBrowsing
                        )
                    } label: {
                        Label("Manage Device", systemImage: "slider.horizontal.3")
                    }
                    Text("Radio, identity, position, time, forwarding, and peer settings, grouped a screen at a time.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    Label(configurationUnavailableReason, systemImage: "lock")
                        .foregroundStyle(.secondary)
                }
            }
            if let provisioning = snapshot.provisioning {
                Section("Radio state") {
                    LabeledContent(
                        "Protocol tier",
                        value: provisioning.hasHostFiltering ? "Full ULCP" : "Transparent baseline"
                    )
                    LabeledContent("Capabilities", value: "\(provisioning.capabilityCount)")
                    LabeledContent("Radio enabled", value: provisioning.phyEnabled ? "Yes" : "No")
                    LabeledContent("Frequency", value: "\(provisioning.frequencyKHz) kHz")
                    LabeledContent("Transmit power", value: "\(provisioning.transmitPowerDBm) dBm")
                    if let bandwidth = provisioning.bandwidthHz {
                        LabeledContent("Bandwidth", value: "\(bandwidth / 1_000) kHz")
                    }
                    if let spreadingFactor = provisioning.spreadingFactor {
                        LabeledContent("Spreading factor", value: "SF\(spreadingFactor)")
                    }
                    if let codingRate = provisioning.codingRateDenominator {
                        LabeledContent("Coding rate", value: "4/\(codingRate)")
                    }
                    if let saved = provisioning.saved {
                        LabeledContent("Saved for restart", value: saved.summary)
                        if let warning = saved.warning {
                            Text(warning)
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }
                    if let dutyNow = provisioning.dutyCycleNow {
                        LabeledContent("Past-hour duty usage", value: formattedDutyCycle(dutyNow))
                    }
                    if let dutyLimit = provisioning.dutyCycleLimit {
                        LabeledContent(
                            "Duty-cycle limit",
                            value: dutyLimit == UInt16.max ? "Disabled" : formattedDutyCycle(dutyLimit)
                        )
                    }
                }

                if provisioning.hasHostFiltering {
                    Section("Host provisioning") {
                        if let filterCount = provisioning.filterCount {
                            LabeledContent("Receive filters", value: "\(filterCount)")
                        }
                        if let channelCount = provisioning.hostChannelCount {
                            LabeledContent("Channel keys", value: "\(channelCount) identifiers")
                        }
                        if let peerCount = provisioning.hostPeerCount {
                            LabeledContent("Peer keys", value: "\(peerCount) public keys")
                        }
                        if let queuedFrames = provisioning.queuedFrames {
                            LabeledContent("Queued frames", value: "\(queuedFrames)")
                        }
                        if let droppedFrames = provisioning.droppedFrames {
                            LabeledContent("Dropped frames", value: "\(droppedFrames)")
                        }
                        if let autoAck = provisioning.autoAcknowledgementEnabled {
                            LabeledContent("Delegated acknowledgements", value: autoAck ? "Enabled" : "Disabled")
                        }
                    }
                }
            }
            if let deviceIdentity = snapshot.deviceIdentity {
                Section("Radio identity") {
                    NavigationLink {
                        PeerDetailView(
                            peer: PeerSummary(
                                id: 0,
                                identity: deviceIdentity,
                                alias: nil,
                                advertisedName: snapshot.name,
                                systemRole: "companion_radio",
                                storedRole: .unknown
                            ),
                            radioSnapshot: $snapshot,
                            conversations: conversations,
                            actions: peerActions,
                            updateDraft: updateDraft,
                            sendMessage: sendMessage,
                            messageActions: messageActions
                        )
                    } label: {
                        LabeledContent("Peer", value: deviceIdentity.hint.text)
                    }
                    Text("System-managed while this radio is saved")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .navigationTitle("Radio")
        .task {
            await refresh()
        }
        .refreshable {
            await refresh()
        }
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Done") { dismiss() }
            }
        }
        .confirmationDialog(
            "Replace the radio's existing host?",
            isPresented: $confirmsHostReplacement,
            titleVisibility: .visible
        ) {
            Button("Replace Host and Clear Its Data", role: .destructive) {
                Task { await claim() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The previous host's keys, filters, and queued traffic will be erased. The radio's own identity and device settings remain unchanged.")
        }
        .confirmationDialog(
            "Forget this companion radio?",
            isPresented: $confirmsForget,
            titleVisibility: .visible
        ) {
            Button("Forget This Radio", role: .destructive) {
                Task {
                    await forget()
                    dismiss()
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The app stops reconnecting to this radio and drops it from Bluetooth's standing connections. The radio keeps its own bond until you re-pair; add it again later with \"Find companion radio\".")
        }
        .confirmationDialog(
            "Factory reset this radio?",
            isPresented: $confirmsFactoryReset,
            titleVisibility: .visible
        ) {
            Button("Erase Everything and Reboot", role: .destructive) {
                Task {
                    do {
                        try await factoryReset()
                        dismiss()
                    } catch {
                        factoryResetProblem = "The factory reset could not be sent. Make sure the radio is still connected, then try again."
                    }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Permanently erases the radio's saved settings, its device identity, and every Bluetooth pairing, then reboots it to a blank factory state. This cannot be undone — you will need to set the radio up again from scratch.")
        }
        .alert(
            "Factory reset failed",
            isPresented: Binding(
                get: { factoryResetProblem != nil },
                set: { if !$0 { factoryResetProblem = nil } }
            )
        ) {
            Button("OK", role: .cancel) { factoryResetProblem = nil }
        } message: {
            Text(factoryResetProblem ?? "")
        }
        .sheet(isPresented: $showsRadioPicker, onDismiss: { Task { await stopDiscovery() } }) {
            NavigationStack {
                RadioPickerView(
                    discoverRadios: discoverRadios,
                    selectRadio: selectRadio,
                    stopDiscovery: stopDiscovery
                )
            }
        }
    }

    private var canEditConfiguration: Bool {
        (snapshot.linkState == .attached || snapshot.linkState == .ready)
            && (snapshot.hostState == .matchesCurrentIdentity || snapshot.hostState == .unsupported)
    }

    /// The radio's own device identity as a peer row, which is what the
    /// unified management sheet keys its cache and screens on. The same
    /// construction the Radio identity section makes.
    private func companionPeer(_ identity: MeshPublicIdentity) -> PeerSummary {
        PeerSummary(
            id: 0,
            identity: identity,
            alias: nil,
            advertisedName: snapshot.name,
            systemRole: "companion_radio",
            storedRole: .unknown
        )
    }

    /// How the management sheet's peer lists open a node from here: the
    /// same peer page they open anywhere else.
    private var companionBrowsing: RemotePeerBrowsing {
        RemotePeerBrowsing(knownPeers: peerActions.knownPeers) { peer in
            AnyView(
                PeerDetailView(
                    peer: peer,
                    radioSnapshot: $snapshot,
                    conversations: conversations,
                    actions: peerActions,
                    updateDraft: updateDraft,
                    sendMessage: sendMessage,
                    messageActions: messageActions
                )
            )
        }
    }

    private var configurationUnavailableReason: String {
        if snapshot.linkState == .configuring {
            return "Radio settings are currently being applied"
        }
        if snapshot.hostState == .unclaimed || snapshot.hostState == .belongsToAnotherIdentity {
            return "Set up this radio for the current phone before editing settings"
        }
        if snapshot.provisioning == nil {
            return "Finish connecting and reading the radio's current settings first"
        }
        if snapshot.deviceIdentity == nil {
            return "This radio has no device identity to manage settings under"
        }
        return "Connect the companion radio to edit its settings"
    }

    /// What stopping means for the step currently in flight: before the link
    /// is up it abandons the attempt, and once the radio is answering it
    /// takes the link down.
    private var inProgressCancelTitle: String {
        switch snapshot.linkState {
        case .scanning: "Stop Looking"
        case .connecting, .reconnecting, .pairing: "Cancel"
        default: "Disconnect"
        }
    }

    @ViewBuilder
    private var connectionControl: some View {
        switch snapshot.linkState {
        case .scanning, .connecting, .reconnecting, .pairing, .provisioning, .configuring,
             .disconnecting:
            HStack {
                ProgressView()
                Text(snapshot.linkState.accessibilityLabel)
                    .foregroundStyle(.secondary)
            }
            // A connection attempt has no deadline of its own — Bluetooth
            // waits indefinitely for a radio that never answers — so the way
            // out stays available at every step rather than appearing only
            // once the link settles.
            if snapshot.linkState != .disconnecting {
                Button(inProgressCancelTitle, role: .destructive) {
                    Task { await disconnect() }
                }
            }
        case .attaching, .synchronizing, .awaitingHost, .attached, .ready:
            if snapshot.hostState == .unclaimed {
                Button("Set Up for This Phone") {
                    Task { await claim() }
                }
            } else if snapshot.hostState == .belongsToAnotherIdentity {
                Button("Replace Existing Host…", role: .destructive) {
                    confirmsHostReplacement = true
                }
            }
            Button("Disconnect", role: .destructive) {
                Task { await disconnect() }
            }
            forgetButton
            factoryResetButton
        case .waitingForRadio:
            VStack(alignment: .leading, spacing: 4) {
                Text("Waiting for the radio to appear")
                Text("Connects automatically when the radio is powered on nearby, even while the app is in the background.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            Button("Stop Waiting", role: .destructive) {
                Task { await disconnect() }
            }
            Button("Find another companion radio") {
                showsRadioPicker = true
            }
            forgetButton
        case .idle, .unavailable, .discovered, .failed:
            if snapshot.localIdentifier != nil {
                Button("Reconnect") {
                    Task { await reconnect() }
                }
                Button("Find another companion radio") {
                    showsRadioPicker = true
                }
                forgetButton
            } else {
                Button("Find companion radio") {
                    showsRadioPicker = true
                }
            }
        }
    }

    @ViewBuilder
    private var forgetButton: some View {
        Button("Forget This Radio", role: .destructive) {
            confirmsForget = true
        }
    }

    @ViewBuilder
    private var factoryResetButton: some View {
        Button("Factory Reset Radio…", role: .destructive) {
            confirmsFactoryReset = true
        }
    }
}
