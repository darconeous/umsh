import CoreLocation
import SwiftUI
import UMSHMobileCore

struct SettingsView: View {
    let identity: LocalIdentitySnapshot?
    let identityError: IdentityVaultError?
    let isLoadingIdentity: Bool
    let createIdentity: () async -> Void
    var advertisedName: String = ""
    var saveAdvertisedName: (String) async -> AppOperationResult = { _ in .failure(.unavailable("Saving is unavailable.")) }
    var advertiseIdentity: () async throws -> Void = { throw MobileAppError.NotRunning }
    var identityShareURI: (() async -> String)? = nil
    /// Whether this phone answers nearby nodes' identity requests, and the
    /// action that changes it. Absent when no mesh session can exist.
    var phoneDiscoverable: Bool = true
    var setPhoneDiscoverable: ((Bool) async -> Void)? = nil
    /// Destroy the private key and come back as a new node, keeping what is
    /// stored; and the same plus every record on the phone.
    var eraseIdentity: () async -> Void = {}
    var startOver: () async -> Void = {}
    @Binding var radioSnapshot: RadioSnapshot
    let connectRadio: () async -> Void
    let reconnectRadio: () async -> Void
    let claimRadio: () async -> Void
    let refreshRadio: () async -> Void
    let disconnectRadio: () async -> Void
    var forgetRadio: () async -> Void = {}
    var factoryResetRadio: () async throws -> Void = {}
    var rebootRadio: () async throws -> Void = {}
    let discoverRadios: () async -> AsyncStream<[DiscoveredRadio]>
    let selectRadio: (UUID) async throws -> Void
    let stopDiscovery: () async -> Void
    /// Records a device met during setup as an ordinary peer. Absent when
    /// there is no identity or store to record it against.
    var saveDevicePeer: ((MeshPublicIdentity, String?, PeerRole?) async throws -> Void)? = nil
    /// What setting up a device asks of the core. Absent when there is no
    /// core to ask.
    var deviceSetupServices: DeviceSetupServices? = nil
    /// Whether a node address is already in this phone's Peers list.
    var isPeerSaved: (String) -> Bool = { _ in false }
    /// Handed to every peer sheet reachable from Settings so those sheets
    /// match the ones opened from Peers.
    var peerActions: PeerActions = .unavailable
    /// The app's conversation list plus messaging closures, threaded to the
    /// radio identity's peer sheet so its "Message" button opens a working
    /// transcript instead of a blank destination.
    var conversations: Binding<[DirectConversationSummary]> = .constant([])
    var messageActions: ChatMessageActions = .unavailable
    var channels: [ChannelSummary] = []
    var channelActions: ChannelActions = .unavailable
    var strandedRadios: [StoredClaimedRadio] = []
    var isRevokingStrandedRadios = false
    var retryRevocation: () async -> Void = {}

    /// Fills a conversation with generated messages, for exercising the
    /// transcript at a size no test account reaches by hand. Only supplied by
    /// debug builds; the control that calls it only exists there too.
    var seedMessages: ((String, Int) async throws -> Void)? = nil

    /// Has a staged peer message this phone after a short delay, to exercise
    /// notifications end to end—arrival, styling, and the inline reply.
    /// Debug builds only, and meaningful only in staging mode.
    var stagedPeerSendsMessage: ((Bool) -> Void)? = nil
    /// Has a staged peer send three channel messages, the middle one lost.
    var stagedPeerLosesChannelMessage: (() -> Void)? = nil
    var stagedPeerReacts: (() -> Void)? = nil
    var stagedPeerReplies: (() -> Void)? = nil
    var stagedPeerMeets: ((Bool) -> Void)? = nil
    var stagedDropTransmissions: ((Bool) -> Void)? = nil
    /// Staging only: whether the managed staged repeater is on the air.
    var stagedRemoteDevicesReachable: ((Bool) -> Void)? = nil

    @Environment(\.regionService) private var regionService
    @State private var showsDeviceSetup = false
    @State private var isSeeding = false
    @State private var failure: FailureNotice?
    #if DEBUG
    /// Read straight from storage, as the announcement schedules above are:
    /// `UMSHApp` reads the same key to decide which store and radio to build,
    /// so a closure round trip would only add a way for the two to disagree.
    @AppStorage("staging.enabled") private var stagingEnabled = false
    @AppStorage("staging.wifiScanOnly") private var stagedWifiScanOnly = false
    @Environment(\.resetStagedData) private var resetStagedData
    @Environment(\.stagedResetFailed) private var stagedResetFailed
    /// Staging only: whether the staged radio is currently dropping everything.
    @State private var dropsTransmissions = false
    /// Staging only: whether the managed staged repeater is off the air.
    @State private var remoteDevicesOutOfReach = false
    @AppStorage("debug.radioTcp.enabled") private var tcpRadioEnabled = false
    @AppStorage("debug.radioTcp.endpoint") private var tcpRadioEndpoint = "127.0.0.1:9000"
    #endif

    private func seedConversation(_ count: Int) async {
        guard let seedMessages, let first = conversations.wrappedValue.first else { return }
        await $failure.attempt(
            String(localized: "Messages Not Generated", comment: "Alert title: the debug filler did not write its messages.")
        ) {
            try await seedMessages(first.conversationAddress, count)
        }
    }

    var body: some View {
        List {
            Section("Identity") {
                if let identity {
                    NavigationLink {
                        IdentityDetailView(
                            identity: identity,
                            radioSnapshot: $radioSnapshot,
                            advertisedName: advertisedName,
                            saveAdvertisedName: saveAdvertisedName,
                            advertiseIdentity: advertiseIdentity,
                            identityShareURI: identityShareURI,
                            phoneDiscoverable: phoneDiscoverable,
                            setPhoneDiscoverable: setPhoneDiscoverable,
                            eraseIdentity: eraseIdentity,
                            startOver: startOver
                        )
                    } label: {
                        PeerRow(hint: identity.publicIdentity.hint, shape: .circle, title: "Your identity")
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
                        ChannelsView(channels: channels, actions: channelActions)
                    } label: {
                        LabeledContent("Channels") {
                            Text("\(channels.filter(\.joinedPhone).count)")
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
                        reboot: rebootRadio,
                        discoverRadios: discoverRadios,
                        selectRadio: selectRadio,
                        stopDiscovery: stopDiscovery,
                        peerActions: peerActions,
                        conversations: conversations,
                        messageActions: messageActions,
                        strandedRadios: strandedRadios,
                        isRevokingStrandedRadios: isRevokingStrandedRadios,
                        retryRevocation: retryRevocation
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
                Text("Configure any nearby UMSH device—a repeater or a tracker—without disturbing this phone's own connection.")
            }

            RegionDatabaseSection(
                version: regionService?.datasetVersion,
                regionCount: regionService?.regionCount,
                problem: regionService?.unavailableMessage
            )

            Section {
                NavigationLink {
                    DiagnosticsView(radio: radioSnapshot)
                } label: {
                    Text("Diagnostics", comment: "Settings row: opens the page with this launch's log and the app's and radio's versions.")
                }
                .accessibilityIdentifier("settings.diagnostics")
            } header: {
                Text("App", comment: "Settings section header: about this app itself, not the mesh or a radio.")
            }

            #if DEBUG
            Section("Interface") {
                NavigationLink("Component Gallery") { ComponentGalleryView() }
            }

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
                Text("Kills the app the way the system does when it reclaims memory, leaving the saved radio's connection armed. Power the radio on, or have another node send a message, and iOS should relaunch this app with no screen at all—far enough to store the message and raise a notification. Debug builds only.")
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
                if stagingEnabled, let stagedPeerSendsMessage {
                    Button("Staged Message in 5 Seconds") {
                        stagedPeerSendsMessage(false)
                    }
                    Button("Staged Channel Message in 5 Seconds") {
                        stagedPeerSendsMessage(true)
                    }
                }
                if stagingEnabled, let stagedPeerLosesChannelMessage {
                    Button("Staged Lost Channel Message") {
                        stagedPeerLosesChannelMessage()
                    }
                }
                if stagingEnabled, let stagedPeerReacts {
                    Button("Staged Reaction in 5 Seconds") {
                        stagedPeerReacts()
                    }
                }
                if stagingEnabled, let stagedPeerReplies {
                    Button("Staged Reply in 5 Seconds") {
                        stagedPeerReplies()
                    }
                }
                if stagingEnabled, let stagedPeerMeets {
                    Button("Staged Peer Opens Add Peer") {
                        stagedPeerMeets(false)
                    }
                    Button("Staged Peer Opens Add Peer and Asks") {
                        stagedPeerMeets(true)
                    }
                }
                // Read once, when the staged air is first built; the air is
                // kept while staging is off, so only a relaunch changes it.
                // Said in the footer rather than left for someone to discover.
                Toggle("Staged device only scans Wi-Fi", isOn: $stagedWifiScanOnly)
                if stagingEnabled, let stagedDropTransmissions {
                    Toggle("Drop everything sent", isOn: $dropsTransmissions)
                        .onChange(of: dropsTransmissions) { _, dropping in
                            stagedDropTransmissions(dropping)
                        }
                }
                if stagingEnabled, let stagedRemoteDevicesReachable {
                    // Distinct from dropping sends: the ask leaves, and
                    // nothing comes back—the shape every mesh-side screen
                    // has to survive.
                    Toggle("Remote device out of reach", isOn: $remoteDevicesOutOfReach)
                        .onChange(of: remoteDevicesOutOfReach) { _, outOfReach in
                            stagedRemoteDevicesReachable(!outOfReach)
                        }
                }
                Button("Reset staged data", role: .destructive) {
                    // The app leaves staging first and erases only once the
                    // staging core has stopped, so nothing is writing to the
                    // database as it empties—and the next time staging is
                    // switched on, the staged mesh is seeded afresh against
                    // that day's clock.
                    guard let resetStagedData else { return }
                    Task { await resetStagedData() }
                }
                if stagedResetFailed {
                    Text("The staged database could not be erased.")
                        .font(.caption)
                        .foregroundStyle(.red)
                }
            } header: {
                Text("Staging")
            } footer: {
                Text("Replaces this phone's data with a fabricated trail-crew mesh—peers, conversations, reactions and map nodes—and reports a companion radio that is attached, charged and holding a fix. For marketing screenshots. Staged content lives in its own database and never touches your real one. The scan-only switch gives the staged device a Wi-Fi receiver and no station, which is the other shape the Wi-Fi screen has to render; it takes effect at the next launch. Debug builds only.")
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
        .failureAlert($failure)
        .sheet(isPresented: $showsDeviceSetup) {
            DeviceSetupFlowView(
                hostIdentity: identity?.publicIdentity,
                companionIdentifier: radioSnapshot.localIdentifier,
                companionName: radioSnapshot.name,
                services: deviceSetupServices,
                saveDevicePeer: saveDevicePeer,
                isPeerSaved: isPeerSaved,
                peerActions: peerActions
            )
        }
    }
}

struct IdentityDetailView: View {
    let identity: LocalIdentitySnapshot
    /// Advertising goes out only through a radio carrying this phone.
    @Binding var radioSnapshot: RadioSnapshot
    var advertisedName: String = ""
    var saveAdvertisedName: (String) async -> AppOperationResult = { _ in .failure(.unavailable("Saving is unavailable.")) }
    var advertiseIdentity: () async throws -> Void = { throw MobileAppError.NotRunning }
    var identityShareURI: (() async -> String)? = nil
    var phoneDiscoverable: Bool = true
    var setPhoneDiscoverable: ((Bool) async -> Void)? = nil
    /// Destroy the private key and come back as a new node, leaving the
    /// messages and contacts on the phone.
    var eraseIdentity: () async -> Void = {}
    /// The same, and the records too.
    var startOver: () async -> Void = {}

    @State private var shareURI = ""
    @State private var nameDraft = ""
    @State private var isAdvertising = false
    @State private var advertiseFeedback: AdvertiseFeedback?
    @State private var failure: FailureNotice?
    @State private var discoverableDraft = true
    @State private var confirmsErase = false
    @State private var confirmsStartOver = false
    /// The second gate on Start Over. Only this one destroys transcripts,
    /// and it is the only thing in the app that does so with no undo.
    @State private var confirmsStartOverAgain = false
    /// Read straight from storage here rather than passed in: these drive
    /// the schedules in `AppRootView`, which reads the same keys, so a
    /// closure round trip would only add a way for the two to disagree.
    @AppStorage("phone.advertIntervalSeconds") private var phoneAdvertInterval = 0
    @AppStorage("phone.beaconIntervalSeconds") private var phoneBeaconInterval = 0
    @AppStorage("phone.shareLocation") private var phoneSharesLocation = false
    /// Optional, so an unset key reads the core's starting value rather than
    /// a literal copy of it; the computed values below fill it in.
    @AppStorage("phone.locationPrecision") private var storedLocationPrecision: Int?
    /// How far what this phone sends may travel, in repeater hops. The
    /// runtime reads the same keys and hands them to the mesh session.
    @AppStorage("phone.floodHops") private var storedFloodHops: Int?
    @AppStorage("phone.beaconFloodHops") private var storedBeaconFloodHops: Int?
    private let limits = CoreLimits.current

    private var phoneLocationPrecision: Int {
        get { Int(CoreLimits.locationPrecision(stored: storedLocationPrecision)) }
        nonmutating set { storedLocationPrecision = newValue }
    }

    private var phoneFloodHops: Int {
        get { Int(CoreLimits.floodHops(stored: storedFloodHops)) }
        nonmutating set { storedFloodHops = newValue }
    }

    private var phoneBeaconFloodHops: Int {
        get { Int(CoreLimits.beaconFloodHops(stored: storedBeaconFloodHops)) }
        nonmutating set { storedBeaconFloodHops = newValue }
    }

    /// Past these, the picker asks for confirmation.
    private var recommendedFloodHops: Int { Int(limits.recommendedFloodHops) }
    private var recommendedBeaconFloodHops: Int { Int(limits.recommendedBeaconFloodHops) }
    /// A reach just picked past its recommended ceiling, held until the
    /// user confirms or the picker is put back.
    @State private var reachWarning: ReachWarning?

    private struct ReachWarning {
        let isBeacon: Bool
        /// The stored value before the pick; nil keeps following the
        /// core's recommended reach.
        let previous: Int?
    }

    var body: some View {
        List {
            Section {
                IdentityHeader(style: .profile) { diameter in
                    PeerAvatar(hint: identity.publicIdentity.hint, shape: .circle, diameter: diameter)
                } content: {
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
                .disabled(isAdvertising || !radioSnapshot.carriesThisPhone)
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
                Text("Runs only while UMSH is open. Intervals are minimums, staggered at random.")
            }

            Section {
                Picker("Messages and requests", selection: Binding(
                    get: { phoneFloodHops },
                    set: { phoneFloodHops = $0 }
                )) {
                    ForEach(1...Int(limits.maxFloodHops), id: \.self) { hops in
                        Text("^[\(hops) hop](inflect: true)").tag(hops)
                    }
                }
                .onChange(of: storedFloodHops) { previous, _ in
                    let before = Int(CoreLimits.floodHops(stored: previous))
                    if phoneFloodHops > recommendedFloodHops, before <= recommendedFloodHops {
                        reachWarning = ReachWarning(isBeacon: false, previous: previous)
                    }
                }
                Picker("Beacon", selection: Binding(
                    get: { phoneBeaconFloodHops },
                    set: { phoneBeaconFloodHops = $0 }
                )) {
                    ForEach(0...Int(limits.maxFloodHops), id: \.self) { hops in
                        if hops == 0 {
                            Text("Direct neighbors only").tag(hops)
                        } else {
                            Text("^[\(hops) hop](inflect: true)").tag(hops)
                        }
                    }
                }
                .onChange(of: storedBeaconFloodHops) { previous, _ in
                    let before = Int(CoreLimits.beaconFloodHops(stored: previous))
                    if phoneBeaconFloodHops > recommendedBeaconFloodHops,
                       before <= recommendedBeaconFloodHops {
                        reachWarning = ReachWarning(isBeacon: true, previous: previous)
                    }
                }
            } header: {
                Text("Reach")
            } footer: {
                Text("The most repeaters a transmission may cross. Channels can set their own.")
            }

            Section {
                Toggle("Share location in identity", isOn: $phoneSharesLocation)
                if phoneSharesLocation {
                    Picker("Shared precision", selection: Binding(
                        get: { phoneLocationPrecision },
                        set: { phoneLocationPrecision = $0 }
                    )) {
                        ForEach(Int(limits.minLocationPrecision)...Int(limits.maxLocationPrecision), id: \.self) { precision in
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
                Text("Never displayed or exported. Survives deleting the app.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            eraseSection
        }
        .navigationTitle("Your identity")
        .transientNoticePresenter()
        .failureAlert($failure)
        .alert(
            "Warning",
            isPresented: Binding(
                get: { reachWarning != nil },
                set: { if !$0 { reachWarning = nil } }
            ),
            presenting: reachWarning
        ) { warning in
            Button("Cancel", role: .cancel) {
                if warning.isBeacon {
                    storedBeaconFloodHops = warning.previous
                } else {
                    storedFloodHops = warning.previous
                }
            }
            Button("Continue") {}
        } message: { warning in
            Text(warning.isBeacon
                 ? "Setting a beacon reach larger than \(recommendedBeaconFloodHops) hops is not recommended. Are you sure you want to do this?"
                 : "Setting a default flood hop count larger than \(recommendedFloodHops) is not recommended. Are you sure you want to do this?")
        }
        .task {
            nameDraft = advertisedName
            discoverableDraft = phoneDiscoverable
            await refreshShareURI()
        }
        .confirmationDialog(
            "Erase This Identity?",
            isPresented: $confirmsErase,
            titleVisibility: .visible
        ) {
            Button("Erase Identity", role: .destructive) {
                Task { await eraseIdentity() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Destroys the private key; this phone becomes a new node. Old messages stay but are unreachable.")
        }
        .confirmationDialog(
            "Start Over?",
            isPresented: $confirmsStartOver,
            titleVisibility: .visible
        ) {
            Button("Erase Everything", role: .destructive) { confirmsStartOverAgain = true }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Your identity, messages, contacts, channels, and paired radio are all erased. UMSH comes back as a first launch.")
        }
        .confirmationDialog(
            "This cannot be undone.",
            isPresented: $confirmsStartOverAgain,
            titleVisibility: .visible
        ) {
            Button("Erase Everything", role: .destructive) {
                Task { await startOver() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Nothing is backed up. Every message on this phone is about to be gone for good.")
        }
    }

    /// The two ways out, ordered by how much they take. Both live under
    /// Storage because that is where the page says what is kept and where.
    private var eraseSection: some View {
        Section {
            Button("Erase Identity…", role: .destructive) { confirmsErase = true }
            Button("Start Over…", role: .destructive) { confirmsStartOver = true }
        } footer: {
            Text("Erase Identity keeps messages; Start Over removes everything.")
        }
    }

    private var advertisedIdentityFooter: String {
        var footer = "Broadcasts your signed public key, name, and capabilities to nearby nodes."
        if setPhoneDiscoverable != nil {
            footer += discoverableDraft
                ? " Discoverable also answers identity requests."
                : " Identity requests are ignored."
        }
        return footer
    }

    private var locationFooter: String {
        guard phoneSharesLocation else {
            return "Your identity says nothing about where you are."
        }
        return "Announcements name a \(precisionLabel(UInt8(clamping: phoneLocationPrecision))) area you are inside. The QR code never carries it."
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
        if case let .failure(error) = await saveAdvertisedName(nameDraft) {
            advertiseFeedback = AdvertiseFeedback(message: error.localizedDescription, isSuccess: false)
            return
        }
        await refreshShareURI()
    }

    private func advertise() async {
        guard !isAdvertising else { return }
        isAdvertising = true
        defer { isAdvertising = false }
        // Any pending name edit rides along with the advertisement.
        if case let .failure(error) = await saveAdvertisedName(nameDraft) {
            advertiseFeedback = AdvertiseFeedback(message: error.localizedDescription, isSuccess: false)
            return
        }
        advertiseFeedback = nil
        let sent = await $failure.attempt(
            String(localized: "Identity Not Advertised", comment: "Alert title: this phone's identity advertisement did not go out. The message says why.")
        ) {
            try await advertiseIdentity()
        }
        guard sent else { return }
        advertiseFeedback = AdvertiseFeedback(
            message: String(
                localized: "Advertisement broadcast",
                comment: "Shown under Advertise Identity once the advertisement went out."
            ),
            isSuccess: true
        )
        await refreshShareURI()
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
    var reboot: () async throws -> Void = {}
    let discoverRadios: () async -> AsyncStream<[DiscoveredRadio]>
    let selectRadio: (UUID) async throws -> Void
    let stopDiscovery: () async -> Void
    /// So the radio's own node identity opens the same peer sheet as any
    /// other node.
    var peerActions: PeerActions = .unavailable
    /// Conversation list plus messaging closures for that peer sheet, so
    /// "Message" there opens a working transcript.
    var conversations: Binding<[DirectConversationSummary]> = .constant([])
    var messageActions: ChatMessageActions = .unavailable
    /// Radios other than this one still holding this phone's identity.
    var strandedRadios: [StoredClaimedRadio] = []
    var isRevokingStrandedRadios = false
    var retryRevocation: () async -> Void = {}
    @Environment(\.dismiss) private var dismiss
    @State private var confirmsHostReplacement = false
    @State private var confirmsForget = false
    @State private var confirmsFactoryReset = false
    /// The last restart or factory reset that could not be sent. One slot
    /// for both: only one of them is ever in flight, and the title says
    /// which it was.
    @State private var failure: FailureNotice?
    /// Both commands fail the same way: the radio link did not carry them.
    /// Fixed rather than the core's reason, since these are link errors, not
    /// the core's.
    private static var radioActionUnsent: String {
        String(localized: "The request did not reach the radio.", comment: "Why a radio restart or factory reset was not sent.")
    }
    @State private var confirmsReboot = false
    @State private var showsRadioPicker = false
    @State private var radioAccessories = RadioAccessories.shared
    #if DEBUG && targetEnvironment(simulator)
    @AppStorage("debug.radioLan.enabled") private var lanRadioEnabled = false
    #endif

    private func strandedRadioRow(_ radio: StoredClaimedRadio) -> some View {
        HStack {
            Label {
                if let name = radio.name {
                    Text("\(name) still holds your identity",
                         comment: "Another radio this phone set up can still acknowledge for it. The placeholder is the radio's name.")
                } else {
                    Text("A radio still holds your identity",
                         comment: "Another radio this phone set up can still acknowledge for it.")
                }
            } icon: {
                Image(systemName: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
            }
            .font(.caption)
            Spacer()
            Button {
                Task { await retryRevocation() }
            } label: {
                Text("Retry", comment: "Button: ask the radio again to let go of this phone's identity.")
            }
            .buttonStyle(.borderless)
            .disabled(isRevokingStrandedRadios
                || !(snapshot.linkState == .attached || snapshot.linkState == .ready))
        }
    }

    var body: some View {
        List {
            #if DEBUG && targetEnvironment(simulator)
            Section {
                Toggle("Local network", isOn: $lanRadioEnabled)
            }
            #endif
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
                ForEach(strandedRadios, id: \.deviceAddress) { radio in
                    strandedRadioRow(radio)
                }
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
                if let manageCompanion = peerActions.manageCompanion,
                   snapshot.provisioning != nil, canEditConfiguration {
                    NavigationLink {
                        let name = snapshot.name ?? String(
                            localized: "Radio",
                            comment: "What to call the attached radio before it reports a name."
                        )
                        ManageDeviceScreen(browsing: companionBrowsing) {
                            try await manageCompanion(name)
                        }
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
                RadioProvisioningSections(provisioning: provisioning)
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
                                systemRole: .companionRadio,
                                storedRole: .unknown
                            ),
                            radioSnapshot: $snapshot,
                            conversations: conversations,
                            actions: peerActions,
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
            "Replace the Radio's Existing Host?",
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
            "Forget This Companion Radio?",
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
            Text(RadioAccessories.usesSystemPicker
                 ? "This removes the saved accessory and stops the app reconnecting. To add it again, open the radio's pairing window and choose Add Another Radio. It does not reset the radio or forget its other hosts."
                 : "The app stops reconnecting to this radio and drops it from Bluetooth's standing connections. The radio keeps its own bond until you re-pair; add it again later with \"Find companion radio\".")
        }
        .confirmationDialog(
            "Restart This Radio?",
            isPresented: $confirmsReboot,
            titleVisibility: .visible
        ) {
            Button("Restart", role: .destructive) {
                Task {
                    do {
                        try await reboot()
                    } catch {
                        failure = FailureNotice(
                            title: String(localized: "Restart Not Sent", comment: "Alert title: the radio was not asked to restart."),
                            message: Self.radioActionUnsent
                        )
                    }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The radio power-cycles and keeps everything it has saved, including its pairing with this phone. It disconnects while it restarts and reconnects on its own.")
        }
        .confirmationDialog(
            "Factory Reset This Radio?",
            isPresented: $confirmsFactoryReset,
            titleVisibility: .visible
        ) {
            Button("Erase Everything and Reboot", role: .destructive) {
                Task {
                    do {
                        try await factoryReset()
                        dismiss()
                    } catch {
                        failure = FailureNotice(
                            title: String(localized: "Factory Reset Not Sent", comment: "Alert title: the radio was not asked to factory reset."),
                            message: Self.radioActionUnsent
                        )
                    }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Permanently erases the radio's saved settings, its device identity, and every Bluetooth pairing, then reboots it to a blank factory state. This cannot be undone—you will need to set the radio up again from scratch.")
        }
        .failureAlert($failure)
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
        if RadioAccessories.usesSystemPicker, radioAccessories.inventory.migrationID != nil {
            RadioAccessoryPickerButton(migrationOnly: true) { _ in await reconnect() }
            Text("Allow this saved radio in the iOS setup dialog, then the app will reconnect. Keep the radio nearby; open its pairing window if it cannot be found.")
                .font(.footnote)
                .foregroundStyle(.secondary)
            Button("Choose a Radio…") { showsRadioPicker = true }
        } else if RadioAccessories.usesSystemPicker, radioAccessories.inventory.needsRadioSetup {
            RadioAccessoryPickerButton(migrationOnly: false, onFinished: selectRadio)
            Text("Keep the radio nearby and open its pairing window. Allow access in the iOS setup dialog.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        } else {
            ordinaryConnectionControl
        }
    }

    @ViewBuilder
    private var ordinaryConnectionControl: some View {
        switch snapshot.linkState {
        case .scanning, .connecting, .reconnecting, .pairing, .provisioning, .configuring,
             .disconnecting:
            HStack {
                ProgressView()
                Text(snapshot.linkState.accessibilityLabel)
                    .foregroundStyle(.secondary)
            }
            // A connection attempt has no deadline of its own—Bluetooth
            // waits indefinitely for a radio that never answers—so the way
            // out stays available at every step rather than appearing only
            // once the link settles.
            if snapshot.linkState != .disconnecting {
                Button(inProgressCancelTitle, role: .destructive) {
                    Task { await disconnect() }
                }
            } else {
                Button("Stop Waiting", role: .destructive) {
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
            if snapshot.provisioning?.supportsReboot == true {
                rebootButton
            }
            forgetButton
            if snapshot.provisioning?.supportsReboot == true {
                factoryResetButton
            }
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

    /// A restart keeps everything, so it sits above the two controls that
    /// do not: it is the one to reach for first when a radio is behaving
    /// oddly, and the only one with nothing to lose by trying.
    @ViewBuilder
    private var rebootButton: some View {
        Button("Restart Radio…", role: .destructive) {
            confirmsReboot = true
        }
    }
}
