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
    let configureRadio: (RadioSettings) async throws -> Void
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
                        configure: configureRadio,
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

            #if DEBUG
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

    /// A precision named by the area it discloses, which is the only
    /// thing about it a person can weigh. Bare sizes, matching the
    /// radio's precision picker.
    private func precisionLabel(_ precision: UInt8) -> String {
        guard let meters = LocationPresentation.cellMeters(precisionBytes: precision) else {
            return "\(precision) bytes"
        }
        return LocationPresentation.cellSizeText(meters: meters)
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
    /// Ask the radio where it is, for the position section. The radio
    /// never volunteers this — see ``RadioPositionPoll``.
    var refreshPosition: (() async -> Void)? = nil
    let configure: (RadioSettings) async throws -> Void
    let disconnect: () async -> Void
    var forget: () async -> Void = {}
    var factoryReset: () async throws -> Void = {}
    var setAlert: (RadioAlertState) async throws -> Void = { _ in }
    var setTime: (UInt32?) async throws -> Void = { _ in }
    var configurePositioning: (UlcpGnssSettingsRecord?, Int16?) async throws -> Void = { _, _ in }
    var configureAdvertising: (UlcpAdvertSettingsRecord?) async throws -> Void = { _ in }
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
    @State private var alertProblem: String?
    @State private var alertRequestInFlight = false
    @State private var clockProblem: String?
    @State private var clockRequestInFlight = false
    @State private var positioningProblem: String?
    @State private var positioningRequestInFlight = false
    /// What was asked for while a positioning write is in flight.
    ///
    /// Without it a toggle would show the tapped position, snap back to
    /// the radio's old value on the next render, and only reach the new
    /// one when the radio answers — a visible flip-flop for the length of
    /// a write and a save. Cleared on completion, at which point the
    /// radio's own answer is what shows, whether the write took or not.
    @State private var pendingPositioning: UlcpGnssSettingsRecord?
    @State private var advertProblem: String?
    @State private var advertRequestInFlight = false
    /// The same optimistic hold as `pendingPositioning`, for the same
    /// reason: the schedule is written as a group and saved.
    @State private var pendingAdvert: UlcpAdvertSettingsRecord?

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
            if let alert = snapshot.alert {
                findSection(alert)
            }
            Section("Configuration") {
                if let provisioning = snapshot.provisioning, canEditConfiguration {
                    NavigationLink {
                        RadioSettingsEditor(
                            snapshot: $snapshot,
                            radioName: snapshot.name,
                            provisioning: provisioning,
                            refresh: refresh,
                            configure: configure
                        )
                    } label: {
                        Label("Edit Device & PHY Settings", systemImage: "slider.horizontal.3")
                    }
                    Text("Device name, frequency, transmit power, bandwidth, spreading factor, and coding rate are shown when supported by this radio.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    Label(configurationUnavailableReason, systemImage: "lock")
                        .foregroundStyle(.secondary)
                }
            }
            // Hidden outright on a radio without CAP_BATTERY: it has no
            // power state to measure, so there is nothing to report as
            // unavailable.
            if snapshot.reportsBattery {
                Section("Power") {
                    // A radio that cannot estimate a level while charging
                    // still reports the rest of its power state, so this
                    // says what is missing rather than "unavailable".
                    LabeledContent(
                        "Battery",
                        value: snapshot.batteryPercentage.map { "\($0)%" } ?? "Level unavailable"
                    )
                    if let millivolts = snapshot.batteryVoltageMillivolts {
                        LabeledContent("Voltage", value: formattedVolts(millivolts))
                    }
                    if let chargeState = snapshot.chargeState {
                        LabeledContent("Charge state", value: chargeState.label)
                    }
                }
            }
            if snapshot.provisioning?.supportsGnss == true {
                positionSection
            }
            if snapshot.provisioning?.supportsAdvert == true {
                announcementsSection
            }
            if snapshot.provisioning?.supportsTime == true {
                clockSection
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
                        LabeledContent("Past-hour duty usage", value: dutyPercentage(dutyNow))
                    }
                    if let dutyLimit = provisioning.dutyCycleLimit {
                        LabeledContent(
                            "Duty-cycle limit",
                            value: dutyLimit == UInt16.max ? "Disabled" : dutyPercentage(dutyLimit)
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
                devicePeersSection
            }
        }
        .navigationTitle("Radio")
        .task {
            await refresh()
        }
        // The position section is live while this sheet is open; the full
        // refresh above happens once, on appear.
        .radioPositionPoll(
            isNeeded: snapshot.provisioning?.supportsGnss == true,
            sample: refreshPosition
        )
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

    private func dutyPercentage(_ value: UInt16) -> String {
        let percent = Double(value) * 100 / Double(UInt16.max)
        return percent.formatted(.number.precision(.fractionLength(percent < 1 ? 2 : 1))) + "%"
    }

    /// The peers stored on the radio's device identity, read back from the
    /// radio itself. Rows are named through this phone's records when the
    /// key is one it knows; managing membership happens on each peer's own
    /// sheet, plus swipe-remove here.
    @ViewBuilder
    private var devicePeersSection: some View {
        if let provisioning = snapshot.provisioning, provisioning.supportsDeviceIdentity,
           let addresses = provisioning.devPeerAddresses {
            Section {
                if addresses.isEmpty {
                    Text("No peers stored on the radio")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(addresses, id: \.self) { address in
                        devicePeerRow(address)
                    }
                }
            } header: {
                Text("Device identity peers (\(addresses.count) of \(devicePeerCapacity))")
            } footer: {
                Text("The radio's own node identity can only communicate with peers whose public keys it holds. Add peers from their pages in Peers.")
            }
        }
    }

    @ViewBuilder
    private func devicePeerRow(_ address: String) -> some View {
        let known = peerActions.knownPeers.first { $0.identity.canonicalAddress == address }
        HStack(spacing: 12) {
            if let known {
                PeerAvatar(hint: known.identity.hint, diameter: 32)
                VStack(alignment: .leading, spacing: 2) {
                    Text(known.displayName)
                    Text(known.identity.hint.text)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } else {
                Image(systemName: "person.crop.circle.badge.questionmark")
                    .foregroundStyle(.secondary)
                Text(address)
                    .font(.caption.monospaced())
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
            if let known, peerActions.removeFromDeviceIdentity != nil {
                Button(role: .destructive) {
                    Task { _ = await peerActions.removeFromDeviceIdentity?(known) }
                } label: {
                    Label("Remove", systemImage: "trash")
                }
            }
        }
    }

    private var canEditConfiguration: Bool {
        (snapshot.linkState == .attached || snapshot.linkState == .ready)
            && (snapshot.hostState == .matchesCurrentIdentity || snapshot.hostState == .unsupported)
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
        return "Connect the companion radio to edit its settings"
    }

    /// "Find This Radio": make a misplaced radio announce itself.
    ///
    /// Shown only when the radio advertises `CAP_ALERT`, and reflects
    /// `PROP_ALERT` rather than what was last asked for — the radio ends
    /// an alert on its own when someone presses its button or its
    /// deadline runs out, and the button follows.
    @ViewBuilder
    private func findSection(_ alert: RadioAlertState) -> some View {
        Section("Find") {
            Button {
                let desired: RadioAlertState = alert.isLocating ? .none : .locating
                alertProblem = nil
                alertRequestInFlight = true
                Task {
                    do {
                        try await setAlert(desired)
                    } catch {
                        alertProblem = "The radio did not answer. It may be out of range."
                    }
                    alertRequestInFlight = false
                }
            } label: {
                Label(
                    alert.isLocating ? "Stop Alert" : "Find This Radio",
                    systemImage: alert.isLocating ? "bell.slash" : "bell.and.waves.left.and.right"
                )
            }
            .disabled(alertRequestInFlight || !canUseRadio)

            if alert.isLocating {
                Text("The radio is announcing itself. It stops when you tap Stop Alert, when someone presses the button on the radio, or after a few minutes — tap Find again to keep it going.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Text("Makes the radio beep or flash — whichever its hardware can do — even if its buzzer is silenced. Keeps going if you walk out of Bluetooth range.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if let alertProblem {
                Label(alertProblem, systemImage: "exclamationmark.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// Where the radio thinks it is, and the policy governing it
    /// (`CAP_GNSS`).
    ///
    /// The policy is editable here rather than only through device setup:
    /// commissioning is for a radio this phone is *not* tethered to, and
    /// switching your own radio's receiver on should not require walking
    /// through a setup flow that also wants to restate its role and
    /// forwarding policy. Each change writes the whole four-property
    /// group and saves, because a receiver running under half a policy is
    /// the thing worth avoiding.
    @ViewBuilder
    private var positionSection: some View {
        Section("Position") {
            let policy = pendingPositioning ?? snapshot.provisioning?.gnss
            let enabled = snapshot.provisioning?.gnss?.enabled
            if let policy {
                Toggle(
                    "GNSS receiver",
                    isOn: positioningBinding(policy, \.enabled)
                )
                Toggle(
                    "Share location in identity",
                    isOn: positioningBinding(policy, \.identUpdate)
                )
                if policy.identUpdate {
                    Picker(
                        "Shared precision",
                        selection: positioningBinding(policy, \.identPrecision)
                    ) {
                        ForEach(UInt8(1)...UInt8(7), id: \.self) { precision in
                            Text(locationCellLabel(precision)).tag(precision)
                        }
                    }
                }
                Toggle(
                    "Trust receiver time",
                    isOn: positioningBinding(policy, \.timeTrust)
                )
            }
            if let position = snapshot.position {
                LabeledContent("Receiver") {
                    Label(
                        position.fixLabel(receiverEnabled: enabled),
                        systemImage: position.fix.symbolName
                    )
                    .labelStyle(.titleAndIcon)
                }
                LabeledContent("Satellites", value: position.satellitesText)
                if let coordinates = position.coordinateText,
                   let latitude = position.latitude,
                   let longitude = position.longitude {
                    LabeledContent("Coordinates") {
                        Text(coordinates)
                            .font(.caption.monospaced())
                    }
                    .coordinateActions(
                        latitude: latitude,
                        longitude: longitude,
                        fractionDigits: position.coordinateDecimals,
                        pinName: snapshot.name
                    )
                    if let cell = position.cellText {
                        LabeledContent("Reported area", value: cell)
                    }
                }
                if let altitude = position.altitudeMeters {
                    LabeledContent("Altitude", value: "\(altitude) m")
                }
                if let accuracy = position.accuracyText {
                    LabeledContent("Accuracy", value: accuracy)
                }
            } else {
                LabeledContent("Receiver", value: enabled == false ? "Off" : "No report yet")
            }
            Text(enabled == false
                 ? "The receiver is powered down to the lowest state this board can reach. On most of them it is the largest continuous load there is."
                 : "A position names a grid cell rather than a point, and the accuracy figure is the receiver's own estimate rather than a measured error.")
                .font(.caption)
                .foregroundStyle(.secondary)
            if let positioningProblem {
                Label(positioningProblem, systemImage: "exclamationmark.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .disabled(positioningRequestInFlight || !canUseRadio)
    }

    /// What the radio says about itself unasked (`CAP_ADVERT`).
    ///
    /// Two schedules rather than one, because the two announcements cost
    /// very different amounts of airtime and say different things: a
    /// beacon is an empty broadcast that collects the path back to this
    /// radio as it travels, while an advertisement carries the signed
    /// identity and reaches only the radio's own neighbours.
    @ViewBuilder
    private var announcementsSection: some View {
        Section("Announcements") {
            if let policy = pendingAdvert ?? snapshot.provisioning?.advert {
                Picker("Beacon", selection: advertBinding(policy, \.beaconIntervalSeconds)) {
                    ForEach(beaconIntervalChoices, id: \.self) { seconds in
                        Text(formattedAnnouncementInterval(seconds)).tag(seconds)
                    }
                }
                Picker("Identity", selection: advertBinding(policy, \.advertIntervalSeconds)) {
                    ForEach(advertisementIntervalChoices, id: \.self) { seconds in
                        Text(formattedAnnouncementInterval(seconds)).tag(seconds)
                    }
                }
                Toggle("Beacon at startup", isOn: advertBinding(policy, \.startupBeacon))
                Text("A beacon publishes the path back to this radio and costs very little. An identity announcement carries this radio's name and role, and only reaches nodes that can hear it directly. Each interval is a minimum: periods run a little longer at random, so radios on the same schedule do not all transmit at once.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if let advertProblem {
                Label(advertProblem, systemImage: "exclamationmark.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .disabled(advertRequestInFlight || !canUseRadio)
    }

    /// A binding over one field of the advertisement policy that writes
    /// the whole policy back, for the reason `positioningBinding` gives.
    private func advertBinding<Value>(
        _ policy: UlcpAdvertSettingsRecord,
        _ field: WritableKeyPath<UlcpAdvertSettingsRecord, Value>
    ) -> Binding<Value> {
        Binding(
            get: { policy[keyPath: field] },
            set: { newValue in
                var desired = policy
                desired[keyPath: field] = newValue
                advertProblem = nil
                advertRequestInFlight = true
                pendingAdvert = desired
                Task {
                    do {
                        try await configureAdvertising(desired)
                    } catch {
                        advertProblem = "The radio did not take that schedule. It still holds the one shown."
                    }
                    pendingAdvert = nil
                    advertRequestInFlight = false
                }
            }
        )
    }

    /// A binding over one field of the positioning policy that writes the
    /// whole policy back to the radio.
    ///
    /// The four properties are written as a set — the radio's own rule,
    /// not this screen's — so a single toggle still sends all of them.
    /// Once the write settles, what shows is the radio's own answer: a
    /// setting it refused springs back to what it actually holds.
    private func positioningBinding<Value>(
        _ policy: UlcpGnssSettingsRecord,
        _ field: WritableKeyPath<UlcpGnssSettingsRecord, Value>
    ) -> Binding<Value> {
        Binding(
            get: { policy[keyPath: field] },
            set: { newValue in
                var desired = policy
                desired[keyPath: field] = newValue
                writePositioning(desired)
            }
        )
    }

    private func writePositioning(_ desired: UlcpGnssSettingsRecord) {
        positioningProblem = nil
        positioningRequestInFlight = true
        pendingPositioning = desired
        Task {
            do {
                try await configurePositioning(
                    desired,
                    snapshot.provisioning?.timeZoneOffsetMinutes
                )
            } catch {
                positioningProblem = "The radio did not take that setting. It still holds the one shown."
            }
            pendingPositioning = nil
            positioningRequestInFlight = false
        }
    }

    /// The zone travels with the positioning policy, since both are saved
    /// device-domain settings written by the same call.
    private func timeZoneBinding(_ offset: Int16) -> Binding<Int16> {
        Binding(
            get: { offset },
            set: { minutes in
                clockProblem = nil
                positioningRequestInFlight = true
                Task {
                    do {
                        try await configurePositioning(
                            snapshot.provisioning?.gnss,
                            minutes
                        )
                    } catch {
                        clockProblem = "The radio did not take that time zone. It still holds the one shown."
                    }
                    positioningRequestInFlight = false
                }
            }
        )
    }

    /// A location precision named by the area it discloses, which is the
    /// only thing about it a person can weigh.
    private func locationCellLabel(_ precision: UInt8) -> String {
        guard let meters = ulcpLocationCellMeters(precisionBytes: precision) else {
            return "\(precision) bytes"
        }
        if meters >= 1_000 {
            return "\((meters / 1_000).formatted(.number.precision(.fractionLength(0)))) km"
        }
        return "\(meters.formatted(.number.precision(.fractionLength(meters < 10 ? 1 : 0)))) m"
    }

    /// The radio's wall clock (`PROP_TIME`), and the one action that
    /// changes it.
    ///
    /// Setting the clock is live and never saved — an epoch stored in
    /// flash comes back arbitrarily wrong, because nothing bounds how long
    /// a radio spends powered off. The time *zone* is saved configuration
    /// and belongs with the rest of the radio's own domain.
    @ViewBuilder
    private var clockSection: some View {
        Section("Time") {
            if let clock = snapshot.clock {
                if let date = clock.date {
                    LabeledContent("Radio clock", value: date.formatted(date: .abbreviated, time: .standard))
                    if let drift = clock.driftSummary() {
                        LabeledContent("Difference", value: drift)
                    }
                } else {
                    LabeledContent("Radio clock", value: "Not set")
                }
            } else {
                LabeledContent("Radio clock", value: "Not read yet")
            }
            if let offset = snapshot.provisioning?.timeZoneOffsetMinutes {
                Picker("Time zone", selection: timeZoneBinding(offset)) {
                    ForEach(deviceTimeZoneOffsets, id: \.self) { candidate in
                        Text(formattedUTCOffset(candidate)).tag(candidate)
                    }
                }
                .disabled(positioningRequestInFlight || !canUseRadio)
            }
            Button {
                clockProblem = nil
                clockRequestInFlight = true
                Task {
                    do {
                        try await setTime(UInt32(Date.now.timeIntervalSince1970))
                    } catch {
                        clockProblem = "The radio did not answer. It may be out of range."
                    }
                    clockRequestInFlight = false
                }
            } label: {
                Label("Set From iPhone", systemImage: "clock.arrow.trianglehead.counterclockwise.rotate.90")
            }
            .disabled(clockRequestInFlight || !canUseRadio)
            Text("The clock is not saved on the radio: a radio that finds its own time from GNSS keeps it, and one that does not starts each power-up not knowing. The zone is saved, and is an offset rather than a place — the radio has no zone database, so it will not follow daylight saving on its own.")
                .font(.caption)
                .foregroundStyle(.secondary)
            if let clockProblem {
                Label(clockProblem, systemImage: "exclamationmark.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
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

    /// Whether the link is far enough along to carry a command.
    private var canUseRadio: Bool {
        switch snapshot.linkState {
        case .attached, .ready: true
        default: false
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

private struct RadioSettingsEditor: View {
    @Binding var snapshot: RadioSnapshot
    let provisioning: RadioProvisioningSummary
    let refresh: () async -> Void
    let configure: (RadioSettings) async throws -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var deviceName: String
    @State private var radioEnabled: Bool
    @State private var frequencyKHz: String
    @State private var transmitPowerDBm: String
    @State private var bandwidthHz: UInt32
    @State private var spreadingFactor: UInt8
    @State private var codingRate: UInt8
    @State private var dutyCycleLimit: UInt16
    @State private var isSaving = false
    @State private var isRefreshing = false
    @State private var problem: String?
    @State private var lastAuthoritativeName: String?
    @State private var lastAuthoritativeProvisioning: RadioProvisioningSummary

    init(
        snapshot: Binding<RadioSnapshot>,
        radioName: String?,
        provisioning: RadioProvisioningSummary,
        refresh: @escaping () async -> Void,
        configure: @escaping (RadioSettings) async throws -> Void
    ) {
        _snapshot = snapshot
        self.provisioning = provisioning
        self.refresh = refresh
        self.configure = configure
        _deviceName = State(initialValue: radioName ?? "")
        _radioEnabled = State(initialValue: provisioning.phyEnabled)
        _frequencyKHz = State(initialValue: String(provisioning.frequencyKHz))
        _transmitPowerDBm = State(initialValue: String(provisioning.transmitPowerDBm))
        _bandwidthHz = State(initialValue: provisioning.bandwidthHz ?? 125_000)
        _spreadingFactor = State(initialValue: provisioning.spreadingFactor ?? 9)
        _codingRate = State(initialValue: provisioning.codingRateDenominator ?? 5)
        _dutyCycleLimit = State(initialValue: provisioning.dutyCycleLimit ?? UInt16.max)
        _lastAuthoritativeName = State(initialValue: radioName)
        _lastAuthoritativeProvisioning = State(initialValue: provisioning)
    }

    var body: some View {
        Form {
            if !unreadableSettings.isEmpty {
                Section {
                    Label("Some settings could not be read", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                } footer: {
                    Text("This radio did not report \(unreadableSettings.formatted(.list(type: .and))). Those settings are not shown here and are left exactly as they are when you save.")
                }
            }

            if provisioning.supportsDeviceName {
                Section("Device") {
                    TextField("Device name", text: $deviceName)
                    Text("The device name is public and may be visible in Bluetooth discovery.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            if showsPresets {
                Section("Preset") {
                    Picker("Radio profile", selection: presetSelection) {
                        Text("Custom / manual").tag("custom")
                        ForEach(RadioPreset.vetted) { preset in
                            Text(preset.name).tag(preset.id)
                        }
                    }
                    Text("A preset changes all radio parameters below. Choose one used by your local mesh; every node must use matching PHY settings.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Section {
                Toggle("Radio enabled", isOn: $radioEnabled)
                LabeledContent("Frequency") {
                    HStack(spacing: 5) {
                        TextField("Frequency", text: $frequencyKHz)
                            .keyboardType(.numberPad)
                            .multilineTextAlignment(.trailing)
                            .accessibilityLabel("Frequency in kilohertz")
                        Text("kHz").foregroundStyle(.secondary)
                    }
                }
                LabeledContent("Transmit power") {
                    HStack(spacing: 5) {
                        TextField("Transmit power", text: $transmitPowerDBm)
                            .keyboardType(.numbersAndPunctuation)
                            .multilineTextAlignment(.trailing)
                            .accessibilityLabel("Transmit power in dBm")
                        Text("dBm").foregroundStyle(.secondary)
                    }
                }
                if showsLoRa {
                    Picker("Bandwidth", selection: $bandwidthHz) {
                        Text("7.81 kHz").tag(UInt32(7_810))
                        Text("10.42 kHz").tag(UInt32(10_420))
                        Text("15.63 kHz").tag(UInt32(15_630))
                        Text("20.83 kHz").tag(UInt32(20_830))
                        Text("31.25 kHz").tag(UInt32(31_250))
                        Text("41.67 kHz").tag(UInt32(41_670))
                        Text("62.5 kHz").tag(UInt32(62_500))
                        Text("125 kHz").tag(UInt32(125_000))
                        Text("250 kHz").tag(UInt32(250_000))
                        Text("500 kHz").tag(UInt32(500_000))
                    }
                    Picker("Spreading factor", selection: $spreadingFactor) {
                        ForEach(UInt8(5)...UInt8(12), id: \.self) { value in
                            Text("SF\(value)").tag(value)
                        }
                    }
                    Picker("Coding rate", selection: $codingRate) {
                        ForEach(UInt8(5)...UInt8(8), id: \.self) { value in
                            Text("4/\(value)").tag(value)
                        }
                    }
                }
            } header: {
                Text("Radio")
            } footer: {
                Text("Changing PHY settings can make this radio unable to communicate with peers using a different configuration.")
            }

            if provisioning.supportsDutyCycleLimit, provisioning.dutyCycleLimit != nil {
                Section {
                    if let usage = snapshot.provisioning?.dutyCycleNow {
                        LabeledContent("Past-hour usage", value: dutyPercentage(usage))
                    }
                    Picker("Transmit limit", selection: $dutyCycleLimit) {
                        ForEach(dutyCycleOptions, id: \.value) { option in
                            Text(option.label).tag(option.value)
                        }
                    }
                } header: {
                    Text("Duty cycle")
                } footer: {
                    Text("The radio drops new transmissions that would exceed this rolling one-hour airtime limit. Disabling the limit does not disable usage measurement.")
                }
            }

            if let problem {
                Section { Text(problem).foregroundStyle(.red) }
            }
        }
        .navigationTitle("Radio settings")
        .task {
            await refreshAndApply()
        }
        .refreshable {
            await refreshAndApply()
        }
        .onChange(of: snapshot) { _, newSnapshot in
            guard !isSaving else { return }
            applyAuthoritativeSnapshot(newSnapshot, force: false)
        }
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Save") { Task { await save() } }
                    .disabled(settings == nil || isSaving || isRefreshing)
            }
        }
    }

    // A radio can advertise a capability and still refuse the properties
    // behind it. Rust leaves those settings out of the snapshot and out of
    // the write, so the form hides them rather than showing a default that
    // reads as the radio's own value.

    /// The modem profile is one setting in three properties: a radio that
    /// reported only part of it has not reported it.
    private var showsLoRa: Bool {
        provisioning.supportsLoRa
            && provisioning.bandwidthHz != nil
            && provisioning.spreadingFactor != nil
            && provisioning.codingRateDenominator != nil
    }

    /// A preset sets every radio parameter at once, so it is only offered
    /// when every parameter it sets is one this radio will accept.
    private var showsPresets: Bool {
        (showsLoRa || !provisioning.supportsLoRa)
            && (provisioning.dutyCycleLimit != nil || !provisioning.supportsDutyCycleLimit)
    }

    private var unreadableSettings: [String] {
        var settings: [String] = []
        if provisioning.supportsLoRa, !showsLoRa { settings.append("its modem settings") }
        if provisioning.supportsDutyCycleLimit, provisioning.dutyCycleLimit == nil {
            settings.append("its transmit limit")
        }
        return settings
    }

    private var settings: RadioSettings? {
        guard let frequency = UInt32(frequencyKHz), frequency > 0,
              let power = Int8(transmitPowerDBm)
        else { return nil }
        let trimmedName = deviceName.trimmingCharacters(in: .whitespacesAndNewlines)
        if provisioning.supportsDeviceName,
           trimmedName.isEmpty || trimmedName.utf8.count > 64 || trimmedName.contains("\0") {
            return nil
        }
        return RadioSettings(
            deviceName: provisioning.supportsDeviceName ? trimmedName : nil,
            phyEnabled: radioEnabled,
            frequencyKHz: frequency,
            transmitPowerDBm: power,
            bandwidthHz: provisioning.supportsLoRa ? bandwidthHz : nil,
            spreadingFactor: provisioning.supportsLoRa ? spreadingFactor : nil,
            codingRateDenominator: provisioning.supportsLoRa ? codingRate : nil,
            dutyCycleLimit: provisioning.supportsDutyCycleLimit ? dutyCycleLimit : nil
        )
    }

    private var presetSelection: Binding<String> {
        Binding(
            get: {
                RadioPreset.vetted.first(where: matches)?.id ?? "custom"
            },
            set: { identifier in
                guard let preset = RadioPreset.vetted.first(where: { $0.id == identifier }) else {
                    return
                }
                radioEnabled = true
                frequencyKHz = String(preset.frequencyKHz)
                transmitPowerDBm = String(preset.transmitPowerDBm)
                bandwidthHz = preset.bandwidthHz
                spreadingFactor = preset.spreadingFactor
                codingRate = preset.codingRate
                dutyCycleLimit = preset.dutyCycleLimit
            }
        )
    }

    private func matches(_ preset: RadioPreset) -> Bool {
        frequencyKHz == String(preset.frequencyKHz)
            && transmitPowerDBm == String(preset.transmitPowerDBm)
            && (!provisioning.supportsLoRa || (
                bandwidthHz == preset.bandwidthHz
                    && spreadingFactor == preset.spreadingFactor
                    && codingRate == preset.codingRate
            ))
            && (!provisioning.supportsDutyCycleLimit || dutyCycleLimit == preset.dutyCycleLimit)
    }

    private var dutyCycleOptions: [(value: UInt16, label: String)] {
        var options: [(UInt16, String)] = [
            (UInt16.max, "Disabled"),
            (13_107, "20%"),
            (6_553, "10%"),
            (655, "1%"),
            (65, "0.1%"),
        ]
        if !options.contains(where: { $0.0 == dutyCycleLimit }) {
            options.append((dutyCycleLimit, "Custom (\(dutyPercentage(dutyCycleLimit)))"))
        }
        return options
    }

    private func dutyPercentage(_ value: UInt16) -> String {
        let percent = Double(value) * 100 / Double(UInt16.max)
        return percent.formatted(.number.precision(.fractionLength(percent < 1 ? 2 : 1))) + "%"
    }

    private func refreshAndApply() async {
        guard !isRefreshing else { return }
        isRefreshing = true
        defer { isRefreshing = false }
        await refresh()
        applyAuthoritativeSnapshot(snapshot, force: true)
    }

    private func applyAuthoritativeSnapshot(_ authoritative: RadioSnapshot, force: Bool) {
        guard let latest = authoritative.provisioning else { return }
        if provisioning.supportsDeviceName,
           force || authoritative.name != lastAuthoritativeName {
            deviceName = authoritative.name ?? ""
        }
        if force || latest.frequencyKHz != lastAuthoritativeProvisioning.frequencyKHz {
            frequencyKHz = String(latest.frequencyKHz)
        }
        if force || latest.phyEnabled != lastAuthoritativeProvisioning.phyEnabled {
            radioEnabled = latest.phyEnabled
        }
        if force || latest.transmitPowerDBm != lastAuthoritativeProvisioning.transmitPowerDBm {
            transmitPowerDBm = String(latest.transmitPowerDBm)
        }
        if let bandwidth = latest.bandwidthHz,
           force || bandwidth != lastAuthoritativeProvisioning.bandwidthHz {
            bandwidthHz = bandwidth
        }
        if let sf = latest.spreadingFactor,
           force || sf != lastAuthoritativeProvisioning.spreadingFactor {
            spreadingFactor = sf
        }
        if let cr = latest.codingRateDenominator,
           force || cr != lastAuthoritativeProvisioning.codingRateDenominator {
            codingRate = cr
        }
        if let limit = latest.dutyCycleLimit,
           force || limit != lastAuthoritativeProvisioning.dutyCycleLimit {
            dutyCycleLimit = limit
        }
        lastAuthoritativeName = authoritative.name
        lastAuthoritativeProvisioning = latest
    }

    private func save() async {
        guard let settings else { return }
        isSaving = true
        defer { isSaving = false }
        let outcome: String?
        do {
            try await configure(settings)
            outcome = nil
        } catch {
            outcome = "The radio rejected these settings. Its previous configuration remains authoritative."
        }
        // What the radio reports back is what the radio is set to, whatever
        // was written — a power clamped to what the hardware can reach, a
        // setting it declined to take. Snapshot updates are ignored while a
        // write is in flight, so the form adopts the result unconditionally
        // here rather than waiting for a later change to differ from it.
        applyAuthoritativeSnapshot(snapshot, force: true)
        guard let outcome else {
            dismiss()
            return
        }
        problem = outcome
    }
}

/// A vetted PHY configuration a whole mesh can agree on.
///
/// Shared with device setup: a repeater the operator commissions has to end
/// up on the same profile as the phone's own radio, and two lists would
/// eventually disagree.
struct RadioPreset: Identifiable {
    let id: String
    let name: String
    let frequencyKHz: UInt32
    let transmitPowerDBm: Int8
    let bandwidthHz: UInt32
    let spreadingFactor: UInt8
    let codingRate: UInt8
    let dutyCycleLimit: UInt16

    static let vetted = [
        RadioPreset(
            id: "meshcore-us-canada",
            name: "MeshCore USA/Canada (recommended)",
            frequencyKHz: 910_525,
            transmitPowerDBm: 20,
            bandwidthHz: 62_500,
            spreadingFactor: 7,
            codingRate: 5,
            dutyCycleLimit: UInt16.max
        ),
        RadioPreset(
            id: "umsh-us-general",
            name: "UMSH US general testing",
            frequencyKHz: 915_000,
            transmitPowerDBm: 14,
            bandwidthHz: 125_000,
            spreadingFactor: 7,
            codingRate: 5,
            dutyCycleLimit: UInt16.max
        ),
    ]
}
