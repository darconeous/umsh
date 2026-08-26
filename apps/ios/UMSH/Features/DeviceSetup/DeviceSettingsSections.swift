import SwiftUI
import UMSHMobileCore

// The sections of the commissioning sheet, one struct each.
//
// Each goal's sheet is the same form rendered from a different section list,
// so a section has to stand on its own: each takes the bindings and closures
// it needs and nothing else. None of them take the flow
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
                    ForEach(ulcpSupportedBandwidthsHz(), id: \.self) { hertz in
                        Text(Self.bandwidthLabel(hertz)).tag(hertz)
                    }
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

    private static func bandwidthLabel(_ hertz: UInt32) -> String {
        let kilohertz = Double(hertz) / 1_000
        return "\(kilohertz.formatted(.number.precision(.fractionLength(0...2)))) kHz"
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

// MARK: - Discoverability

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

    var body: some View {
        Section {
            Toggle("GNSS receiver", isOn: $enabled)
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

    private func precisionLabel(_ precision: UInt8) -> String {
        LocationPresentation.precisionLabel(precisionBytes: precision)
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
