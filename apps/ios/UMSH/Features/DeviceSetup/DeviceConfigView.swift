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
    @State private var timeZoneOffsetMinutes: Int16
    @State private var gnssEnabled: Bool
    @State private var gnssIdentUpdate: Bool
    @State private var gnssIdentPrecision: UInt8
    @State private var gnssTimeTrust: Bool

    @State private var isSaving = false
    @State private var alertRequestInFlight = false
    @State private var alertProblem: String?
    @State private var clockRequestInFlight = false
    @State private var clockProblem: String?
    /// The configuration the device confirmed, as the form ended up holding
    /// it. Kept rather than a flag so that adopting a value the device
    /// reported back does not read as an unsaved edit, and so any real edit
    /// after a write clears the confirmation on its own.
    @State private var appliedConfiguration: UlcpDeviceConfigRecord?
    @State private var verificationProblem: String?

    private var applied: Bool {
        appliedConfiguration != nil && appliedConfiguration == configuration
    }

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
        // A device with no zone set is one nobody has told where it is,
        // and the phone doing the setup is standing next to it.
        _timeZoneOffsetMinutes = State(initialValue: sync.tzOffsetMin ?? phoneUTCOffsetMinutes)
        let gnss = sync.gnss
        _gnssEnabled = State(initialValue: gnss?.enabled ?? false)
        _gnssIdentUpdate = State(initialValue: gnss?.identUpdate ?? false)
        _gnssIdentPrecision = State(initialValue: gnss?.identPrecision ?? 5)
        _gnssTimeTrust = State(initialValue: gnss?.timeTrust ?? true)
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

            if !unreadableSettings.isEmpty {
                Section {
                    Label("Some settings could not be read", systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.orange)
                } footer: {
                    Text("This device did not report \(unreadableSettings.formatted(.list(type: .and))). Those settings are not shown here and are left exactly as they are when you apply changes. Everything else works normally.")
                }
            }

            ownershipSection

            if let alert = controller.snapshot.alert {
                findSection(alert)
            }

            if sync.supportsBattery {
                powerSection
            }

            if sync.supportsDeviceName {
                Section {
                    TextField("Device name", text: $deviceName)
                } header: {
                    Text("Device")
                } footer: {
                    Text("The device name is public and may be visible in Bluetooth discovery.")
                }
            }

            if showsPresets {
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
            }

            radioSection

            if showsIdentity {
                identitySection
            }

            if showsPositioning {
                positioningSection
            }

            if sync.supportsTime {
                timeSection
            }

            if sync.supportsRepeater, sync.repeater != nil {
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

    /// Make the device announce itself, so the one being configured can be
    /// picked out of a bench full of identical boards.
    ///
    /// Shown only when the device advertises `CAP_ALERT`, and it reflects
    /// `PROP_ALERT` rather than what was last asked for — the device ends an
    /// alert on its own when someone presses its button or its deadline runs
    /// out, and the control follows.
    @ViewBuilder
    private func findSection(_ alert: RadioAlertState) -> some View {
        Section {
            Button {
                let desired: RadioAlertState = alert.isLocating ? .none : .locating
                alertProblem = nil
                alertRequestInFlight = true
                Task {
                    do {
                        try await controller.setAlert(desired)
                    } catch {
                        alertProblem = "The device did not answer. It may have moved out of range."
                    }
                    alertRequestInFlight = false
                }
            } label: {
                Label(
                    alert.isLocating ? "Stop Alert" : "Find This Device",
                    systemImage: alert.isLocating ? "bell.slash" : "bell.and.waves.left.and.right"
                )
            }
            .disabled(alertRequestInFlight || isLinkDown)
            if let alertProblem {
                Label(alertProblem, systemImage: "exclamationmark.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        } header: {
            Text("Find")
        } footer: {
            Text(alert.isLocating
                ? "The device is announcing itself. It stops when you tap Stop Alert, when someone presses the button on it, or after a few minutes. An alert left running keeps running after you close this sheet."
                : "Makes the device beep or flash — whichever its hardware can do — even if its buzzer is silenced. This is not a saved setting.")
        }
    }

    /// What the device reports about its own power, as measured rather than
    /// configured. Each row appears only when the device publishes that
    /// field: level, terminal voltage, and charge state are independently
    /// optional in `PROP_BATTERY`.
    @ViewBuilder
    private var powerSection: some View {
        Section {
            LabeledContent(
                "Battery",
                value: controller.snapshot.batteryPercentage.map { "\($0)%" }
                    ?? "Level unavailable"
            )
            if let millivolts = controller.snapshot.batteryVoltageMillivolts {
                LabeledContent("Voltage", value: formattedVolts(millivolts))
            }
            if let chargeState = controller.snapshot.chargeState {
                LabeledContent("Charge state", value: chargeState.label)
            }
        } header: {
            Text("Power")
        } footer: {
            Text("Read from the device when this session started, and again whenever it reports a change.")
        }
    }

    /// The receiver and what is done with a fix.
    ///
    /// The switch and the three policy settings are written as a set —
    /// Rust puts the switch last, so a receiver that starts looking does
    /// it under the disclosure and trust policy on this form rather than
    /// the one the device happened to be holding.
    @ViewBuilder
    private var positioningSection: some View {
        Section {
            Toggle("GNSS receiver", isOn: $gnssEnabled)
            if let position = controller.snapshot.position {
                LabeledContent("Fix", value: position.fixLabel(receiverEnabled: sync.gnss?.enabled))
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
                        pinName: controller.snapshot.name
                    )
                }
            }
            Toggle("Share location in identity", isOn: $gnssIdentUpdate)
            if gnssIdentUpdate {
                Picker("Shared precision", selection: $gnssIdentPrecision) {
                    ForEach(UInt8(1)...UInt8(7), id: \.self) { precision in
                        Text(precisionLabel(precision)).tag(precision)
                    }
                }
            }
            Toggle("Trust receiver time", isOn: $gnssTimeTrust)
        } header: {
            Text("Positioning")
        } footer: {
            Text(positioningFooter)
        }
    }

    private var positioningFooter: String {
        var footer = gnssEnabled
            ? "The receiver is usually the largest continuous load on a battery-powered node."
            : "The receiver is powered down to the lowest state this board can reach."
        footer += gnssIdentUpdate
            ? " Nodes that can read this device's identity are told a \(precisionLabel(gnssIdentPrecision)) area it is inside — never a more precise position than that."
            : " The device does not put its location in the identity it advertises."
        footer += gnssTimeTrust
            ? " Fixes set the device's clock."
            : " Fixes never touch the clock, so a hand-set time is safe from a jammed or spoofed sky. Positions are unaffected."
        return footer
    }

    /// A precision named by the area it discloses, which is the only thing
    /// about it a person can weigh.
    private func precisionLabel(_ precision: UInt8) -> String {
        guard let meters = ulcpLocationCellMeters(precisionBytes: precision) else {
            return "\(precision) bytes"
        }
        if meters >= 1_000 {
            return "\((meters / 1_000).formatted(.number.precision(.fractionLength(0)))) km"
        }
        return "\(meters.formatted(.number.precision(.fractionLength(meters < 10 ? 1 : 0)))) m"
    }

    /// The device's zone, which is saved, and its clock, which is not.
    ///
    /// They are on the same screen and travel by different routes for a
    /// reason worth stating: an epoch in flash comes back arbitrarily
    /// wrong, because nothing bounds how long a device spends powered off.
    @ViewBuilder
    private var timeSection: some View {
        Section {
            if showsTimeZone {
                Picker("Time zone", selection: $timeZoneOffsetMinutes) {
                    ForEach(deviceTimeZoneOffsets, id: \.self) { offset in
                        Text(formattedUTCOffset(offset)).tag(offset)
                    }
                }
            }
            if let clock = controller.snapshot.clock {
                LabeledContent(
                    "Device clock",
                    value: clock.date?.formatted(date: .abbreviated, time: .standard) ?? "Not set"
                )
            }
            Button {
                clockProblem = nil
                clockRequestInFlight = true
                Task {
                    do {
                        try await controller.setTime(epochSeconds: UInt32(Date.now.timeIntervalSince1970))
                    } catch {
                        clockProblem = "The device did not answer. It may have moved out of range."
                    }
                    clockRequestInFlight = false
                }
            } label: {
                Label("Set Clock From iPhone", systemImage: "clock.arrow.trianglehead.counterclockwise.rotate.90")
            }
            .disabled(clockRequestInFlight || isLinkDown)
            if let clockProblem {
                Label(clockProblem, systemImage: "exclamationmark.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        } header: {
            Text("Time")
        } footer: {
            Text(showsTimeZone
                 ? "The zone is an offset, not a place: the device has no zone database, so it will not follow daylight saving on its own. Setting the clock takes effect immediately and is not saved — it is not part of Apply."
                 : "Setting the clock takes effect immediately and is not saved — it is not part of Apply.")
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
            if sync.supportsDutyCycleLimit, sync.dutyCycleLimit != nil {
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
            if showsDiscoverable {
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
        if showsDiscoverable {
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

    // MARK: - Unreadable settings

    // A device can advertise a capability and still refuse the properties
    // behind it — firmware older than the capability it reports. Rust
    // leaves those settings out of the snapshot and out of the write, so
    // the form hides them rather than showing a default that reads as the
    // device's own value and edits that would silently go nowhere.

    /// The modem profile is one setting in three properties: a device that
    /// reported only part of it has not reported it.
    private var showsLoRa: Bool {
        sync.supportsLora
            && sync.bandwidthHz != nil
            && sync.spreadingFactor != nil
            && sync.codingRateDenom != nil
    }

    /// Mobility stands in for the whole advertised identity — the role
    /// alone cannot be told apart, because an empty role is also the
    /// device saying it derives its own.
    private var showsIdentity: Bool { sync.supportsIdent && sync.identMobile != nil }

    private var showsDiscoverable: Bool {
        sync.supportsDeviceIdentity && sync.devDiscoverable != nil
    }

    /// The positioning policy is one setting in four properties: a device
    /// that reported only part of it has not reported it.
    private var showsPositioning: Bool { sync.supportsGnss && sync.gnss != nil }

    /// The zone alone. A device that would not report it can still be
    /// given a clock, so only the picker hides — the section stays.
    private var showsTimeZone: Bool { sync.supportsTime && sync.tzOffsetMin != nil }

    /// A preset sets every radio parameter at once, so it is only offered
    /// when every parameter it sets is one this device will accept.
    private var showsPresets: Bool {
        (showsLoRa || !sync.supportsLora)
            && (sync.dutyCycleLimit != nil || !sync.supportsDutyCycleLimit)
    }

    /// What the device would not report, named the way the form names it.
    private var unreadableSettings: [String] {
        var settings: [String] = []
        if sync.supportsLora, !showsLoRa { settings.append("its modem settings") }
        if sync.supportsDutyCycleLimit, sync.dutyCycleLimit == nil {
            settings.append("its transmit limit")
        }
        if sync.supportsIdent, !showsIdentity { settings.append("its advertised identity") }
        if sync.supportsDeviceIdentity, !showsDiscoverable { settings.append("discoverability") }
        if sync.supportsRepeater, sync.repeater == nil { settings.append("its forwarding policy") }
        if sync.supportsGnss, !showsPositioning { settings.append("its positioning settings") }
        if sync.supportsTime, !showsTimeZone { settings.append("its time zone") }
        return settings
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
                : nil,
            tzOffsetMin: sync.supportsTime ? timeZoneOffsetMinutes : nil,
            gnss: sync.supportsGnss
                ? UlcpGnssSettingsRecord(
                    enabled: gnssEnabled,
                    identUpdate: gnssIdentUpdate,
                    identPrecision: gnssIdentPrecision,
                    timeTrust: gnssTimeTrust
                )
                : nil
        )
    }

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
        // A device answers each write with the value it holds, and that
        // answer stands whatever was asked for — transmit power comes back
        // clamped to what the radio can reach. The form shows the device's
        // figure, not the operator's, so nobody walks away believing this
        // radio transmits at a power it cannot produce.
        transmitPowerDBm = String(readback.transmitPowerDbm)
        // The separate question of what it reports after its save, which is
        // what it will boot with.
        if let mismatch = firstMismatch(between: configuration, and: readback) {
            verificationProblem = """
                The device saved its settings but reported \(mismatch) back \
                differently. Read it again before relying on this configuration.
                """
            return
        }
        appliedConfiguration = self.configuration
    }

    /// The first field the device reports differently from what was asked
    /// for, named for a human. Device name is excluded: it is reported on
    /// the session snapshot rather than in the sync record.
    ///
    /// Settings the device does not report are excluded as well. They were
    /// never written, so there is nothing to hold the readback to — the
    /// unreadable-settings notice already says so, and calling it a
    /// mismatch would send the operator looking for a fault that is not
    /// there.
    ///
    /// Transmit power is excluded for the same reason: a device clamps it to
    /// what its radio can reach, so a device asked for more than it has
    /// reports back less by design. The fields left here are the ones a
    /// device refuses outright rather than adjusts, where a readback that
    /// disagrees really is one.
    private func firstMismatch(
        between requested: UlcpDeviceConfigRecord,
        and readback: UlcpSyncRecord
    ) -> String? {
        func reported<Value: Equatable>(
            _ asked: Value?,
            _ read: Value?,
            _ name: String
        ) -> String? {
            guard let read else { return nil }
            return asked == read ? nil : name
        }

        if requested.radio.phyEnabled != readback.phyEnabled { return "the radio switch" }
        if requested.radio.frequencyKhz != readback.frequencyKhz { return "the frequency" }
        return reported(requested.radio.bandwidthHz, readback.bandwidthHz, "the bandwidth")
            ?? reported(
                requested.radio.spreadingFactor,
                readback.spreadingFactor,
                "the spreading factor"
            )
            ?? reported(
                requested.radio.codingRateDenom,
                readback.codingRateDenom,
                "the coding rate"
            )
            ?? reported(
                requested.radio.dutyCycleLimit,
                readback.dutyCycleLimit,
                "the duty-cycle limit"
            )
            // An unreadable role and a device-derived role are both an
            // absent value, so the only role worth checking is one the
            // device names.
            ?? reported(requested.identRole, readback.identRole, "the advertised role")
            ?? reported(requested.identMobile, readback.identMobile, "device mobility")
            ?? reported(requested.devDiscoverable, readback.devDiscoverable, "discoverability")
            ?? reported(requested.repeater, readback.repeater, "the repeater policy")
            ?? reported(requested.tzOffsetMin, readback.tzOffsetMin, "the time zone")
            ?? reported(requested.gnss, readback.gnss, "the positioning settings")
    }
}
