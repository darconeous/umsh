import SwiftUI
import UMSHMobileCore

// The sections of the device settings form, one struct each.
//
// A setup sheet and the full editor are the same form rendered from different
// section lists, so a section has to stand on its own: each takes the bindings
// and closures it needs and nothing else. None of them take the flow
// controller — a section that could reach the session could also reach the
// device, and then "which screens can write to this device" stops being
// answerable by reading the call site.

// MARK: - Notices

/// What is wrong before anything on the form can be trusted: a link that has
/// dropped, and settings the device would not report.
struct LinkNoticesSection: View {
    /// Non-nil once the link has failed, holding what to say about it.
    let connectionProblem: String?
    let unreadableSettings: [String]

    var body: some View {
        if let connectionProblem {
            Section {
                Label(connectionProblem, systemImage: "exclamationmark.triangle.fill")
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
                Text("This device did not report \(unreadableSettings.formatted(.list(type: .and))). Those settings are not shown here and are set to this sheet's values when you apply changes, because the device accepts its configuration whole. Everything else works normally.")
            }
        }
    }
}

/// What this goal will not manage on this device — stated plainly rather than
/// left as sections that are quietly missing.
///
/// Not a warning: none of it stops the device being set up, and dressing a
/// hardware fact as a problem would send the operator looking for a fault.
struct SetupNoteSection: View {
    let note: String

    var body: some View {
        Section {
            Text(note)
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }
}

// MARK: - Ownership

/// Whose device this is, and the node identity it carries.
struct DeviceOwnershipSection: View {
    let hostState: RadioHostState
    /// The device's own identity presented as an ordinary node, or nil when it
    /// does not expose one.
    let peer: PeerSummary?
    let peerActions: PeerActions
    let savePeer: (() async -> Bool)?
    let isPeerSaved: (String) -> Bool

    var body: some View {
        Section {
            LabeledContent("Set up for", value: hostState.label)
            if let peer {
                // The device's own node identity, shown through the same
                // screen every other node uses — the operator commissioning
                // a repeater needs its address, not a four-character hint.
                NavigationLink {
                    PeerDetailView(
                        peer: peer,
                        radioSnapshot: .constant(.idle),
                        actions: administrationActions,
                        savePeer: savePeer,
                        isPeerSaved: isPeerSaved(peer.identity.canonicalAddress)
                    )
                } label: {
                    HStack(spacing: 12) {
                        PeerAvatar(hint: peer.identity.hint, diameter: 32)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Device identity")
                            Text(peer.identity.hint.text)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } else {
                LabeledContent("Device identity", value: "Not exposed")
            }
        } footer: {
            switch hostState {
            case .belongsToAnotherIdentity:
                Text("This device is another phone's companion radio. You can change its settings; its host keys, filters, and queued traffic are left alone.")
            case .unclaimed:
                Text("No phone owns this device. Setting it up here does not claim it — it keeps working on its own.")
            default:
                Text("Changing settings here does not claim the device for this phone.")
            }
        }
    }

    /// The peer sheet opened from here administers a nearby device and has no
    /// conversation list to land a transcript in, so messaging is simply not
    /// offered rather than offered and broken.
    private var administrationActions: PeerActions {
        var actions = peerActions
        actions.startConversation = nil
        return actions
    }
}

/// The one thing about ownership that should interrupt a setup.
///
/// Someone else's radio is the case that makes a session consequential, and it
/// is the only one worth a row: an unclaimed device is the ordinary case, and
/// saying "not configured" about a board out of its box is noise.
struct ForeignRadioSection: View {
    let hostState: RadioHostState

    var body: some View {
        if hostState == .belongsToAnotherIdentity {
            Section {
                Label("Another phone's radio", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
            } footer: {
                Text("This device is another phone's companion radio. Setting it up here changes what it does; its host keys, filters, and queued traffic are left alone.")
            }
        }
    }
}

// MARK: - Find

/// Make the device announce itself, so the one being configured can be
/// picked out of a bench full of identical boards.
///
/// Shown only when the device advertises `CAP_ALERT`, and it reflects
/// `PROP_ALERT` rather than what was last asked for — the device ends an
/// alert on its own when someone presses its button or its deadline runs
/// out, and the control follows.
struct DeviceFindSection: View {
    let alert: RadioAlertState
    /// The device cannot take another request right now — the link is down, or
    /// a write is in flight. A session runs one exchange at a time and refuses
    /// a second outright, so offering this during a save would produce a
    /// failure that says nothing about the device.
    let isBusy: Bool
    /// What to say when the request does not come back. Supplied rather
    /// than written here because silence means different things on the two
    /// transports: a device on the bench is out of range, and one across
    /// the mesh may simply not take orders from this phone.
    let failureText: String
    let setAlert: (RadioAlertState) async throws -> Void

    @State private var requestInFlight = false
    @State private var problem: String?

    var body: some View {
        Section {
            Button {
                let desired: RadioAlertState = alert.isLocating ? .none : .locating
                problem = nil
                requestInFlight = true
                Task {
                    do {
                        try await setAlert(desired)
                    } catch {
                        problem = failureText
                    }
                    requestInFlight = false
                }
            } label: {
                Label(
                    alert.isLocating ? "Stop Alert" : "Find This Device",
                    systemImage: alert.isLocating ? "bell.slash" : "bell.and.waves.left.and.right"
                )
            }
            .disabled(requestInFlight || isBusy)
            if let problem {
                Label(problem, systemImage: "exclamationmark.circle")
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
}

// MARK: - Power

/// What the device reports about its own power, as measured rather than
/// configured. Each row appears only when the device publishes that
/// field: level, terminal voltage, and charge state are independently
/// optional in `PROP_BATTERY`.
struct DevicePowerSection: View {
    let percentage: Int?
    let voltageMillivolts: Int?
    let chargeState: RadioChargeState?
    /// Whether the device volunteers a new reading when this one changes.
    /// It does over the local link and does not across the mesh, where
    /// what is shown is what the last read found.
    let reportsChanges: Bool

    var body: some View {
        Section {
            LabeledContent("Battery", value: percentage.map { "\($0)%" } ?? "Level unavailable")
            if let voltageMillivolts {
                LabeledContent("Voltage", value: formattedVolts(voltageMillivolts))
            }
            if let chargeState {
                LabeledContent("Charge state", value: chargeState.label)
            }
        } header: {
            Text("Power")
        } footer: {
            Text(reportsChanges
                ? "Read from the device when this session started, and again whenever it reports a change."
                : "Read from the device when its settings were last read. It is not watched from here, so reopening this screen is what asks again.")
        }
    }
}

// MARK: - Name

/// What to call this device.
///
/// Labeled in the row rather than only by a section header: a bare text field
/// showing a value says nothing about what the value is, and a header reading
/// "Device" said even less. `Required` is not decoration — a device that
/// accepts a name will not accept an empty one, and an empty field is what
/// keeps Apply disabled.
struct DeviceNameSection: View {
    @Binding var name: String

    var body: some View {
        Section {
            LabeledContent("Name") {
                TextField("Required", text: $name)
                    .multilineTextAlignment(.trailing)
            }
        } footer: {
            Text("The device name is public and may be visible in Bluetooth discovery.")
        }
    }
}

// MARK: - Radio

/// The whole PHY profile named at once, for an operator who knows which mesh
/// they are joining rather than which spreading factor it uses.
struct RadioPresetSection: View {
    @Binding var presetIdentifier: String

    var body: some View {
        Section {
            Picker("Radio profile", selection: $presetIdentifier) {
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
}

/// Every radio parameter, one control each.
struct RadioSection: View {
    @Binding var enabled: Bool
    @Binding var frequencyKHz: String
    @Binding var transmitPowerDBm: String
    let showsLoRa: Bool
    @Binding var bandwidthHz: UInt32
    @Binding var spreadingFactor: UInt8
    @Binding var codingRate: UInt8
    let showsDutyCycleLimit: Bool
    let dutyCycleOptions: [(value: UInt16, label: String)]
    @Binding var dutyCycleLimit: UInt16

    var body: some View {
        Section {
            Toggle("Radio enabled", isOn: $enabled)
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
            if showsDutyCycleLimit {
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
}

/// The PHY as one row, for a sheet that decided it rather than asking.
///
/// This is the one assumed value a setup sheet shows, because its failure mode
/// is silent: a node on the wrong profile is not broken, it is alone. The row
/// carries the numbers as well as the profile's name, so copying a handheld's
/// transmit power onto a mast-mounted repeater is something the operator can
/// see and correct.
struct RadioProfileSection: View {
    let resolution: ResolvedRadioProfile
    /// False only while a required choice is outstanding.
    let chosen: Bool
    /// The vetted profile the radio fields currently spell out, if any.
    let presetName: String?
    /// Those fields as one line of numbers.
    let summary: String
    let destination: () -> RadioProfileEditorView

    var body: some View {
        Section {
            NavigationLink {
                destination()
            } label: {
                LabeledContent("Radio profile") {
                    if needsChoice {
                        Text("Choose").foregroundStyle(.orange)
                    } else {
                        VStack(alignment: .trailing, spacing: 2) {
                            Text(presetName ?? "Custom")
                            Text(summary)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
        } header: {
            Text("Radio")
        } footer: {
            Text(footer)
        }
    }

    private var needsChoice: Bool { resolution.requiresChoice && !chosen }

    private var footer: String {
        let warning = " Nodes on different profiles cannot hear each other."
        switch resolution {
        case let .copied(_, source, _):
            let from = source.map { "Copied from \($0)." } ?? "Copied from this phone's radio."
            return from + warning
        case let .mustChoose(reason):
            guard needsChoice else { return "Set for this device." + warning }
            return reason.text + " Choose the profile your local mesh uses before continuing."
        case let .leftAsFound(reason):
            return reason.text
                + " This device is left on the profile it already had."
                + warning
        }
    }
}

extension ResolvedRadioProfile.MissingReason {
    var text: String {
        switch self {
        case .noCompanion:
            "This phone has no companion radio to copy a profile from."
        case .companionHasNoModemProfile:
            "This phone's radio did not report its modem settings, so there was nothing to copy."
        }
    }
}

/// Everything behind the radio-profile row, on its own screen.
struct RadioProfileEditorView: View {
    @Bindable var draft: DeviceConfigDraft

    var body: some View {
        Form {
            if draft.showsPresets {
                RadioPresetSection(presetIdentifier: $draft.presetIdentifier)
            }
            RadioSection(
                enabled: $draft.radioEnabled,
                frequencyKHz: $draft.frequencyKHz,
                transmitPowerDBm: $draft.transmitPowerDBm,
                showsLoRa: draft.showsLoRa,
                bandwidthHz: $draft.bandwidthHz,
                spreadingFactor: $draft.spreadingFactor,
                codingRate: $draft.codingRate,
                showsDutyCycleLimit: draft.showsDutyCycleLimit,
                dutyCycleOptions: draft.dutyCycleOptions,
                dutyCycleLimit: $draft.dutyCycleLimit
            )
        }
        .navigationTitle("Radio Profile")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// MARK: - Advertised identity

/// What the device says it is, as distinct from what it does.
struct AdvertisedIdentitySection: View {
    @Binding var role: UInt8?
    @Binding var mobile: Bool
    let showsDiscoverable: Bool
    @Binding var discoverable: Bool
    /// What the device will tell the mesh it is, once these settings are in
    /// force — derived by the draft, because an empty role is a device saying
    /// it works its own out.
    let advertisedRole: String

    var body: some View {
        Section {
            Picker("Role", selection: $role) {
                Text("Derive from what it does").tag(UInt8?.none)
                ForEach(PeerRole.selectable) { role in
                    Text(role.label).tag(role.roleCode)
                }
            }
            Toggle("Device moves around", isOn: $mobile)
            if showsDiscoverable {
                Toggle("Discoverable", isOn: $discoverable)
            }
        } header: {
            Text("Advertised identity")
        } footer: {
            Text(footer)
        }
    }

    private var footer: String {
        var footer = "Advertises as: \(advertisedRole). \(mobile ? "Peers are told it is mobile." : "Peers are told it is stationary.")"
        if showsDiscoverable {
            footer += discoverable
                ? " Answers nearby nodes that ask it to identify itself."
                : " Ignores nearby nodes that ask it to identify itself."
        }
        return footer
    }
}

/// Whether the device answers a node that asks it who it is.
///
/// The one part of the advertised identity a setup sheet asks about: the role
/// and the mobility flag follow from the goal, but whether a device answers
/// strangers is a decision about this device in this place.
struct DiscoverabilitySection: View {
    @Binding var discoverable: Bool

    var body: some View {
        Section {
            Toggle("Discoverable", isOn: $discoverable)
        } header: {
            Text("Discoverability")
        } footer: {
            Text(discoverable
                 ? "Answers nearby nodes that ask it to identify itself."
                 : "Ignores nearby nodes that ask it to identify itself. It still announces itself on its own schedule.")
        }
    }
}

// MARK: - Positioning

/// What the device reports about where it is, which is a reading and not a
/// setting: absent on a setup sheet, where nothing has been applied yet and
/// there is nothing to watch.
struct PositioningReadout {
    let position: RadioPosition
    /// The receiver switch as the device reports it *now*, so the fix label
    /// describes the device rather than the unsaved form.
    let receiverEnabled: Bool?
    let pinName: String?
}

/// The receiver and what is done with a fix.
///
/// The switch and the three policy settings are written as a set —
/// Rust puts the switch last, so a receiver that starts looking does
/// it under the disclosure and trust policy on this form rather than
/// the one the device happened to be holding.
struct PositioningSection: View {
    @Binding var enabled: Bool
    @Binding var identUpdate: Bool
    @Binding var identPrecision: UInt8
    @Binding var timeTrust: Bool
    /// Present in the editor, absent on a setup sheet.
    let readout: PositioningReadout?

    var body: some View {
        Section {
            Toggle("GNSS receiver", isOn: $enabled)
            if let readout {
                let position = readout.position
                LabeledContent(
                    "Fix",
                    value: position.fixLabel(receiverEnabled: readout.receiverEnabled)
                )
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
                        pinName: readout.pinName
                    )
                }
            }
            Toggle("Share location in identity", isOn: $identUpdate)
            if identUpdate {
                Picker("Shared precision", selection: $identPrecision) {
                    ForEach(UInt8(1)...UInt8(7), id: \.self) { precision in
                        Text(precisionLabel(precision)).tag(precision)
                    }
                }
            }
            Toggle("Trust receiver time", isOn: $timeTrust)
        } header: {
            Text("Positioning")
        } footer: {
            Text(footer)
        }
    }

    private var footer: String {
        var footer = enabled
            ? "The receiver is usually the largest continuous load on a battery-powered node."
            : "The receiver is powered down to the lowest state this board can reach."
        footer += identUpdate
            ? " Nodes that can read this device's identity are told a \(precisionLabel(identPrecision)) area it is inside — never a more precise position than that."
            : " The device does not put its location in the identity it advertises."
        footer += timeTrust
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
}

// MARK: - Announcements

/// What the device says about itself unasked, on its own schedule.
struct AnnouncementsSection: View {
    @Binding var beaconIntervalSeconds: UInt32
    @Binding var advertIntervalSeconds: UInt32
    @Binding var startupBeacon: Bool

    var body: some View {
        Section {
            Picker("Beacon", selection: $beaconIntervalSeconds) {
                ForEach(beaconIntervalChoices, id: \.self) { seconds in
                    Text(formattedAnnouncementInterval(seconds)).tag(seconds)
                }
            }
            Picker("Identity", selection: $advertIntervalSeconds) {
                ForEach(advertisementIntervalChoices, id: \.self) { seconds in
                    Text(formattedAnnouncementInterval(seconds)).tag(seconds)
                }
            }
            Toggle("Beacon at startup", isOn: $startupBeacon)
        } header: {
            Text("Announcements")
        } footer: {
            Text(footer)
        }
    }

    private var footer: String {
        var footer = beaconIntervalSeconds > 0
            ? "A beacon carries no payload and collects the path back to this device as it travels, so it publishes a route for very little airtime."
            : "The device sends no beacons, so nothing refreshes the mesh's route back to it."
        footer += advertIntervalSeconds > 0
            ? " An identity announcement carries this device's name, role, and capabilities, and reaches only the nodes that can hear it directly."
            : " The device announces its identity only when asked."
        if beaconIntervalSeconds > 0 || advertIntervalSeconds > 0 {
            footer += " Each interval is a minimum: periods run a little longer at random, so devices on the same schedule do not all transmit at once."
        }
        return footer
    }
}

// MARK: - Time

/// The device's zone, which is saved, and its clock, which is not.
///
/// They are on the same screen and travel by different routes for a
/// reason worth stating: an epoch in flash comes back arbitrarily
/// wrong, because nothing bounds how long a device spends powered off.
struct DeviceTimeSection: View {
    let showsTimeZone: Bool
    @Binding var timeZoneOffsetMinutes: Int16
    let clock: RadioClock?
    /// As on `DeviceFindSection`: down, or already talking to the device.
    let isBusy: Bool
    let setTime: (UInt32) async throws -> Void

    @State private var requestInFlight = false
    @State private var problem: String?

    var body: some View {
        Section {
            if showsTimeZone {
                Picker("Time zone", selection: $timeZoneOffsetMinutes) {
                    ForEach(deviceTimeZoneOffsets, id: \.self) { offset in
                        Text(formattedUTCOffset(offset)).tag(offset)
                    }
                }
            }
            if let clock {
                LabeledContent(
                    "Device clock",
                    value: clock.date?.formatted(date: .abbreviated, time: .standard) ?? "Not set"
                )
            }
            Button {
                problem = nil
                requestInFlight = true
                Task {
                    do {
                        try await setTime(UInt32(Date.now.timeIntervalSince1970))
                    } catch {
                        problem = "The device did not answer. It may have moved out of range."
                    }
                    requestInFlight = false
                }
            } label: {
                Label("Set Clock From iPhone", systemImage: "clock.arrow.trianglehead.counterclockwise.rotate.90")
            }
            .disabled(requestInFlight || isBusy)
            if let problem {
                Label(problem, systemImage: "exclamationmark.circle")
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
}

// MARK: - Apply status

/// How the last write went, at the foot of the form.
struct ApplyStatusSection: View {
    let problem: String?
    let applied: Bool

    var body: some View {
        if let problem {
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
    }
}
