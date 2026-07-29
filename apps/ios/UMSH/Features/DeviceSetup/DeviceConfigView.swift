import SwiftUI
import UMSHMobileCore

/// The editor for one administered device.
///
/// Every flow ends here, on the same form, against the same device domain.
/// The goal chosen at the start only decides what the fields start at — a
/// tracker and a repeater are two properties apart, and the operator can
/// see and change both either way.
///
/// The whole form is written as one record: Rust owns the ordering (the PHY
/// is disabled first and re-enabled last, and the save rides the tail), so
/// a device is never left running half a configuration.
struct DeviceConfigView: View {
    let controller: AdminFlowController
    let sync: UlcpSyncRecord
    let isPeerSaved: (String) -> Bool
    let peerActions: PeerActions
    let finish: () -> Void

    @State private var deviceName: String
    @State private var radioEnabled: Bool
    @State private var frequencyKHz: String
    @State private var transmitPowerDBm: String
    @State private var bandwidthHz: UInt32
    @State private var spreadingFactor: UInt8
    @State private var codingRate: UInt8
    @State private var dutyCycleLimit: UInt16
    @State private var identRole: UInt8?
    @State private var identMobile: Bool
    @State private var devDiscoverable: Bool
    @State private var repeaterEnabled: Bool
    @State private var regions: [Data]
    @State private var defaultRegion: Data?
    @State private var minRssiDBm: Int16?
    @State private var minSnrDB: Int8?

    @State private var isSaving = false
    @State private var applied = false
    @State private var verificationProblem: String?

    init(
        controller: AdminFlowController,
        sync: UlcpSyncRecord,
        isPeerSaved: @escaping (String) -> Bool = { _ in false },
        peerActions: PeerActions = .unavailable,
        finish: @escaping () -> Void
    ) {
        self.controller = controller
        self.sync = sync
        self.isPeerSaved = isPeerSaved
        self.peerActions = peerActions
        self.finish = finish

        let goal = controller.goal
        let repeater = sync.repeater
        _deviceName = State(initialValue: controller.snapshot.name ?? "")
        _radioEnabled = State(initialValue: sync.phyEnabled)
        _frequencyKHz = State(initialValue: String(sync.frequencyKhz))
        _transmitPowerDBm = State(initialValue: String(sync.transmitPowerDbm))
        _bandwidthHz = State(initialValue: sync.bandwidthHz ?? 125_000)
        _spreadingFactor = State(initialValue: sync.spreadingFactor ?? 9)
        _codingRate = State(initialValue: sync.codingRateDenom ?? 5)
        _dutyCycleLimit = State(initialValue: sync.dutyCycleLimit ?? UInt16.max)
        // A tracker says what it is. A repeater leaves the role empty on
        // purpose: the device derives "repeater" from the fact that it is
        // forwarding, so the advertised role cannot drift from the truth.
        _identRole = State(initialValue: goal == .tracker ? PeerRole.tracker.roleCode : sync.identRole)
        _identMobile = State(initialValue: goal == .tracker ? true : (sync.identMobile ?? false))
        _devDiscoverable = State(initialValue: sync.devDiscoverable ?? true)
        _repeaterEnabled = State(initialValue: goal == .repeaterNode ? true : (repeater?.enabled ?? false))
        _regions = State(initialValue: repeater?.regions ?? [])
        _defaultRegion = State(initialValue: repeater?.defaultRegion)
        _minRssiDBm = State(initialValue: repeater?.minRssiDbm)
        _minSnrDB = State(initialValue: repeater?.minSnrDb)
    }

    var body: some View {
        Form {
            if controller.snapshot.linkState == .failed {
                Section {
                    Label(
                        controller.snapshot.problemDescription ?? "Connection lost",
                        systemImage: "exclamationmark.triangle.fill"
                    )
                    .foregroundStyle(.red)
                } footer: {
                    Text("Go back and connect to the device again. Nothing was changed on it.")
                }
            }

            ownershipSection

            if sync.supportsDeviceName {
                Section {
                    TextField("Device name", text: $deviceName)
                } header: {
                    Text("Device")
                } footer: {
                    Text("The device name is public and may be visible in Bluetooth discovery.")
                }
            }

            Section {
                Picker("Radio profile", selection: presetSelection) {
                    Text("Custom / manual").tag("custom")
                    ForEach(RadioPreset.vetted) { preset in
                        Text(preset.name).tag(preset.id)
                    }
                }
            } header: {
                Text("Preset")
            } footer: {
                Text("A preset sets every radio parameter below. Choose the one your local mesh uses; nodes with different PHY settings cannot hear each other.")
            }

            radioSection

            if sync.supportsIdent {
                identitySection
            }

            if sync.supportsRepeater {
                RepeaterSettingsSection(
                    enabled: $repeaterEnabled,
                    regions: $regions,
                    defaultRegion: $defaultRegion,
                    minRssiDBm: $minRssiDBm,
                    minSnrDB: $minSnrDB
                )
            }

            if let problem = controller.problem ?? verificationProblem {
                Section { Text(problem).foregroundStyle(.red) }
            }

            if applied {
                Section {
                    Label("Saved on the device", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                } footer: {
                    Text("The device read its settings back after saving, so they survive a power cycle.")
                }
            }

            promotionSection
        }
        .navigationTitle(controller.snapshot.name ?? "Device")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                if applied {
                    Button("Done") { finish() }
                } else {
                    Button("Apply") { Task { await apply() } }
                        .disabled(configuration == nil || isSaving || isLinkDown)
                }
            }
        }
        .onChange(of: configurationFingerprint) { _, _ in
            // Any edit after a successful write puts the form back in the
            // unsaved state, so "Done" never dismisses over pending changes.
            applied = false
        }
    }

    // MARK: - Sections

    /// The peer sheet opened from here administers a nearby device and has no
    /// conversation list to land a transcript in, so messaging is simply not
    /// offered rather than offered and broken.
    private var administrationActions: PeerActions {
        var actions = peerActions
        actions.startConversation = nil
        return actions
    }

    @ViewBuilder
    private var ownershipSection: some View {
        Section {
            LabeledContent("Set up for", value: controller.snapshot.hostState.label)
            if let identity = controller.snapshot.deviceIdentity {
                // The device's own node identity, shown through the same
                // screen every other node uses — the operator commissioning
                // a repeater needs its address, not a four-character hint.
                NavigationLink {
                    PeerDetailView(
                        peer: administeredPeer(identity),
                        radioSnapshot: .constant(.idle),
                        actions: administrationActions,
                        savePeer: controller.canSavePeer
                            ? { await controller.savePeer(role: advertisedPeerRole) }
                            : nil,
                        isPeerSaved: isPeerSaved(identity.canonicalAddress)
                    )
                } label: {
                    HStack(spacing: 12) {
                        PeerAvatar(hint: identity.hint, diameter: 32)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Device identity")
                            Text(identity.hint.text)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } else {
                LabeledContent("Device identity", value: "Not exposed")
            }
        } footer: {
            switch controller.snapshot.hostState {
            case .belongsToAnotherIdentity:
                Text("This device is another phone's companion radio. You can change its settings; its host keys, filters, and queued traffic are left alone.")
            case .unclaimed:
                Text("No phone owns this device. Setting it up here does not claim it — it keeps working on its own.")
            default:
                Text("Changing settings here does not claim the device for this phone.")
            }
        }
    }

    @ViewBuilder
    private var radioSection: some View {
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
            if sync.supportsLora {
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
            if sync.supportsDutyCycleLimit {
                Picker("Transmit limit", selection: $dutyCycleLimit) {
                    ForEach(dutyCycleOptions, id: \.value) { option in
                        Text(option.label).tag(option.value)
                    }
                }
            }
        } header: {
            Text("Radio")
        } footer: {
            Text("Changing PHY settings can leave this device unable to reach peers on a different configuration.")
        }
    }

    @ViewBuilder
    private var identitySection: some View {
        Section {
            Picker("Role", selection: $identRole) {
                Text("Derive from what it does").tag(UInt8?.none)
                ForEach(PeerRole.selectable) { role in
                    Text(role.label).tag(role.roleCode)
                }
            }
            Toggle("Device moves around", isOn: $identMobile)
            if sync.supportsDeviceIdentity {
                Toggle("Discoverable", isOn: $devDiscoverable)
            }
        } header: {
            Text("Advertised identity")
        } footer: {
            Text(identityFooter)
        }
    }

    private var identityFooter: String {
        var footer = "Advertises as: \(advertisedRole). \(identMobile ? "Peers are told it is mobile." : "Peers are told it is stationary.")"
        if sync.supportsDeviceIdentity {
            footer += devDiscoverable
                ? " Answers nearby nodes that ask it to identify itself."
                : " Ignores nearby nodes that ask it to identify itself."
        }
        return footer
    }

    @ViewBuilder
    private var promotionSection: some View {
        if controller.goal != .companion, let identifier = controller.snapshot.identifier {
            Section {
                Button("Use as This Phone's Radio") {
                    controller.requestPromotion(identifier)
                }
                .disabled(controller.isBusy || isLinkDown)
            } footer: {
                Text(controller.companionName.map {
                    "Replaces \($0) as this phone's companion radio and ends this setup session."
                } ?? "Binds this device as this phone's companion radio and ends this setup session.")
            }
        }
    }

    // MARK: - Derived state

    private var isLinkDown: Bool {
        controller.snapshot.linkState == .failed || controller.snapshot.linkState == .idle
    }

    /// What the device will tell the mesh it is, which is derived when no
    /// role is configured: a forwarding node is a repeater, anything else
    /// is a tracker.
    private var advertisedRole: String {
        guard let identRole else {
            return repeaterEnabled && sync.supportsRepeater ? "Repeater" : "Tracker"
        }
        return PeerRole.label(forCode: identRole)
    }

    /// The device presented as an ordinary node, so it can be shown through
    /// the shared peer screen. There is no stored row behind it — that is
    /// precisely what the save action on that screen is for.
    private func administeredPeer(_ identity: MeshPublicIdentity) -> PeerSummary {
        PeerSummary(
            id: 0,
            identity: identity,
            alias: nil,
            advertisedName: controller.snapshot.name,
            isContact: false,
            systemRole: nil,
            storedRole: advertisedPeerRole
        )
    }

    /// What the device advertises *today*, from its reported settings rather
    /// than the unsaved form — a peer record must not be filed under a role
    /// the device has not been given yet.
    private var advertisedPeerRole: PeerRole {
        guard let role = sync.identRole else {
            return sync.repeater?.enabled == true ? .repeater : .unknown
        }
        return PeerRole(roleCode: role)
    }

    private var configuration: UlcpDeviceConfigRecord? {
        guard let frequency = UInt32(frequencyKHz), frequency > 0,
              let power = Int8(transmitPowerDBm)
        else { return nil }
        let trimmedName = deviceName.trimmingCharacters(in: .whitespacesAndNewlines)
        if sync.supportsDeviceName,
           trimmedName.isEmpty || trimmedName.utf8.count > 64 || trimmedName.contains("\0") {
            return nil
        }
        return UlcpDeviceConfigRecord(
            radio: UlcpRadioSettingsRecord(
                deviceName: sync.supportsDeviceName ? trimmedName : nil,
                phyEnabled: radioEnabled,
                frequencyKhz: frequency,
                transmitPowerDbm: power,
                bandwidthHz: sync.supportsLora ? bandwidthHz : nil,
                spreadingFactor: sync.supportsLora ? spreadingFactor : nil,
                codingRateDenom: sync.supportsLora ? codingRate : nil,
                dutyCycleLimit: sync.supportsDutyCycleLimit ? dutyCycleLimit : nil
            ),
            // Every optional here has to match what the device advertised:
            // sending a domain it does not have, or omitting one it does, is
            // a client bug and Rust rejects it before anything is written.
            identRole: sync.supportsIdent ? identRole : nil,
            identMobile: sync.supportsIdent ? identMobile : nil,
            devDiscoverable: sync.supportsDeviceIdentity ? devDiscoverable : nil,
            repeater: sync.supportsRepeater
                ? UlcpRepeaterSettingsRecord(
                    enabled: repeaterEnabled,
                    regions: regions,
                    defaultRegion: defaultRegion,
                    minRssiDbm: minRssiDBm,
                    minSnrDb: minSnrDB
                )
                : nil
        )
    }

    /// Everything a write would carry, so an edit after a save is noticed.
    private var configurationFingerprint: UlcpDeviceConfigRecord? { configuration }

    private var presetSelection: Binding<String> {
        Binding(
            get: { RadioPreset.vetted.first(where: matches)?.id ?? "custom" },
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
            && (!sync.supportsLora || (
                bandwidthHz == preset.bandwidthHz
                    && spreadingFactor == preset.spreadingFactor
                    && codingRate == preset.codingRate
            ))
            && (!sync.supportsDutyCycleLimit || dutyCycleLimit == preset.dutyCycleLimit)
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
            let percent = Double(dutyCycleLimit) * 100 / Double(UInt16.max)
            let text = percent.formatted(.number.precision(.fractionLength(percent < 1 ? 2 : 1)))
            options.append((dutyCycleLimit, "Custom (\(text)%)"))
        }
        return options
    }

    // MARK: - Applying

    private func apply() async {
        guard let configuration else { return }
        isSaving = true
        verificationProblem = nil
        defer { isSaving = false }
        guard let readback = await controller.configure(configuration) else { return }
        // The write itself is echo-verified property by property inside
        // Rust. This is the second question: what the device reports after
        // its save, which is what it will boot with.
        if let mismatch = firstMismatch(between: configuration, and: readback) {
            verificationProblem = """
                The device saved its settings but reported \(mismatch) back \
                differently. Read it again before relying on this configuration.
                """
            return
        }
        applied = true
    }

    /// The first field the device reports differently from what was asked
    /// for, named for a human. Device name is excluded: it is reported on
    /// the session snapshot rather than in the sync record.
    private func firstMismatch(
        between requested: UlcpDeviceConfigRecord,
        and readback: UlcpSyncRecord
    ) -> String? {
        if requested.radio.phyEnabled != readback.phyEnabled { return "the radio switch" }
        if requested.radio.frequencyKhz != readback.frequencyKhz { return "the frequency" }
        if requested.radio.transmitPowerDbm != readback.transmitPowerDbm { return "transmit power" }
        if requested.radio.bandwidthHz != readback.bandwidthHz { return "the bandwidth" }
        if requested.radio.spreadingFactor != readback.spreadingFactor {
            return "the spreading factor"
        }
        if requested.radio.codingRateDenom != readback.codingRateDenom { return "the coding rate" }
        if requested.radio.dutyCycleLimit != readback.dutyCycleLimit {
            return "the duty-cycle limit"
        }
        if requested.identRole != readback.identRole { return "the advertised role" }
        if requested.identMobile != readback.identMobile { return "device mobility" }
        if requested.devDiscoverable != readback.devDiscoverable { return "discoverability" }
        if requested.repeater != readback.repeater { return "the repeater policy" }
        return nil
    }
}
