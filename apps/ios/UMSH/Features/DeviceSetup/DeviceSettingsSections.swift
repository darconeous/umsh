import SwiftUI
import UMSHMobileCore

// The sections of the commissioning sheet, one struct each.
//
// Each goal's sheet is the same form rendered from a different section list,
// so a section has to stand on its own: each takes the bindings and closures
// it needs and nothing else. None of them take the flow
// controller—a section that could reach the session could also reach the
// device, and then "which screens can write to this device" stops being
// answerable by reading the call site.

// MARK: - Notices

/// What is wrong before anything on the form can be trusted: a link that has
/// dropped, and settings the device would not report.
struct LinkNoticesSection: View {
    /// Non-nil once the link has failed, holding what to say about it.
    let connectionProblem: String?
    let unreadable: [MobileSetupUnreadable]

    var body: some View {
        if let connectionProblem {
            Section {
                Label(connectionProblem, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
            } footer: {
                Text("Go back and connect to the device again. Nothing was changed on it.")
            }
        }

        if !unreadable.isEmpty {
            Section {
                Label("Some settings could not be read", systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.orange)
                ForEach(unreadable, id: \.self) { setting in
                    Text(setting.title)
                }
            } footer: {
                Text("These are not shown and are left as they are when you apply.", comment: "Device setup: footer under the settings the device did not report.")
            }
        }
    }
}

/// What this goal will not manage on this device—stated plainly rather than
/// left as sections that are quietly missing.
///
/// Not a warning: none of it stops the device being set up, and dressing a
/// hardware fact as a problem would send the operator looking for a fault.
struct SetupNoteSection: View {
    let notes: [MobileSetupNote]

    var body: some View {
        Section {
            ForEach(notes, id: \.self) { note in
                Text(note.text)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
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
/// "Device" said even less. `Required` is not decoration—a device that
/// accepts a name will not accept an empty one, and an empty field is what
/// keeps Apply disabled. A name the device cannot take says why under the
/// label.
struct DeviceNameSection: View {
    @Binding var name: String
    let problem: String?

    var body: some View {
        Section {
            LabeledContent {
                TextField("Required", text: $name)
                    .multilineTextAlignment(.trailing)
            } label: {
                RemoteFieldTitle("Name", problem: problem)
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
    /// The vetted preset the radio fields spell out; `nil` is custom.
    let presetID: String?
    let adopt: (String) -> Void

    var body: some View {
        Section {
            Picker("Radio profile", selection: Binding(
                get: { presetID ?? Self.custom },
                set: { chosen in
                    guard chosen != Self.custom else { return }
                    adopt(chosen)
                }
            )) {
                Text("Custom / manual").tag(Self.custom)
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

    /// The picker's row for parameters no vetted preset spells out.
    private static let custom = "custom"
}

/// A picker's rows over a list the core offers: each offered value, then
/// the value the field holds when it is not one of them, which the picker
/// must still show or the next pick would silently rewrite it.
struct ChoiceListRows: View {
    let list: MobileChoiceList?
    let label: (Int64) -> String

    var body: some View {
        ForEach(list?.offered ?? [], id: \.self) { value in
            Text(verbatim: label(value)).choiceTag(value)
        }
        if let other = list?.other {
            Text("Custom (\(label(other)))", comment: "A picker row for a value the device holds that is not one of the offered choices. The placeholder is that value.")
                .choiceTag(other)
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
    let profile: MobileSetupProfile
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
                    if profile.needsChoice(chosen: chosen) {
                        Text("Choose").foregroundStyle(.orange)
                    } else {
                        VStack(alignment: .trailing, spacing: 2) {
                            if let presetName {
                                Text(verbatim: presetName)
                            } else {
                                Text("Custom", comment: "Device setup: the radio profile is not one of the vetted presets.")
                            }
                            Text(verbatim: summary)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }
        } header: {
            Text("Radio")
        } footer: {
            Text(profile.footer(chosen: chosen))
        }
    }
}

/// The radio fields as one line of numbers, for the radio-profile row.
enum RadioProfileSummary {
    static func text(_ radio: MobileRadioDraft, showsModem: Bool, locale: Locale = .current) -> String {
        let frequency = Measurement(value: Double(radio.frequencyKhz.value) / 1_000, unit: UnitFrequency.megahertz)
            .formatted(
                .measurement(
                    width: .abbreviated,
                    usage: .asProvided,
                    numberFormatStyle: .number.precision(.fractionLength(0...3)).grouping(.never)
                )
                .locale(locale)
            )
        let power = SignalPresentation.powerText(Int(radio.transmitPowerDbm.value), locale: locale)
        guard showsModem,
              let hertz = radio.bandwidth.value,
              let factor = radio.spreadingFactor.value,
              let rate = radio.codingRate.value
        else {
            return String(
                localized: "\(frequency) · \(power)",
                locale: locale,
                comment: "Device setup: a radio profile as one line. The placeholders are the frequency and the transmit power, each with its unit."
            )
        }
        let bandwidth = RadioValuePresentation.bandwidth(UInt32(clamping: hertz))
        return String(
            localized: "\(frequency) · \(bandwidth) BW · SF\(factor) · 4/\(rate) · \(power)",
            locale: locale,
            comment: "Device setup: a radio profile as one line: frequency, bandwidth, spreading factor, coding rate, and transmit power, each figure with its unit. BW is bandwidth, SF the spreading factor."
        )
    }
}

/// Everything behind the radio-profile row, on its own screen.
struct RadioProfileEditorView: View {
    @Bindable var model: DeviceSetupModel

    var body: some View {
        let setup = model.snapshot
        let choices = model.review?.choices
        let radio = model.draft.radio
        Form {
            if setup.showsPresets {
                RadioPresetSection(presetID: model.review?.presetId, adopt: model.adoptPreset)
            }
            Section {
                RemoteToggleField("Radio enabled", field: $model.draft.radio.enabled)
                RemoteIntegerField(
                    "Frequency",
                    unit: "kHz",
                    field: model.radioNumber(.frequency, \.frequencyKhz),
                    problem: model.problem(for: radio.frequencyKhz.propertyId)
                )
                RemoteIntegerField(
                    "Transmit power",
                    unit: "dBm",
                    field: model.radioNumber(.transmitPower, \.transmitPowerDbm),
                    signed: true,
                    problem: model.problem(for: radio.transmitPowerDbm.propertyId)
                )
                if setup.showsModem {
                    RemoteChoiceField("Bandwidth", field: model.radioChoice(.bandwidth, \.bandwidth)) {
                        ChoiceListRows(list: choices?.bandwidthsHz) {
                            RadioValuePresentation.bandwidth(UInt32(clamping: $0))
                        }
                    }
                    RemoteChoiceField("Spreading factor", field: model.radioChoice(.spreadingFactor, \.spreadingFactor)) {
                        ChoiceListRows(list: choices?.spreadingFactors) {
                            String(localized: "SF\($0)", comment: "A LoRa spreading factor, such as SF9. SF is the usual abbreviation.")
                        }
                    }
                    RemoteChoiceField("Coding rate", field: model.radioChoice(.codingRate, \.codingRate)) {
                        ChoiceListRows(list: choices?.codingRates) {
                            String(localized: "4/\($0)", comment: "A LoRa coding rate, such as 4/5.")
                        }
                    }
                }
                if setup.showsDutyLimit {
                    RemoteChoiceField("Transmit limit", field: model.radioChoice(.dutyLimit, \.dutyLimit)) {
                        ChoiceListRows(list: choices?.dutyLimits) { limit in
                            limit == Int64(UInt16.max)
                                ? String(localized: "Disabled", comment: "A transmit limit of none.")
                                : formattedDutyCycle(UInt16(clamping: limit))
                        }
                    }
                }
            } header: {
                Text("Radio")
            } footer: {
                Text("Changing PHY settings can leave this device unable to reach peers on a different configuration.")
            }
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
/// The switch and the three policy settings are written as a set—
/// Rust puts the switch last, so a receiver that starts looking does
/// it under the disclosure and trust policy on this form rather than
/// the one the device happened to be holding.
struct PositioningSection: View {
    @Binding var enabled: Bool
    @Binding var identUpdate: Bool
    @Binding var identPrecision: Int64?
    let precisions: MobileChoiceList?
    @Binding var timeTrust: Bool

    var body: some View {
        Section {
            Toggle("GNSS receiver", isOn: $enabled)
            Toggle("Share location in identity", isOn: $identUpdate)
            if identUpdate {
                Picker("Shared precision", selection: $identPrecision) {
                    ChoiceListRows(list: precisions) { precisionLabel($0) }
                }
            }
            Toggle("Trust receiver time", isOn: $timeTrust)
        } header: {
            Text("Positioning")
        } footer: {
            VStack(alignment: .leading, spacing: 4) {
                if enabled {
                    Text("The receiver is usually the largest continuous load on a battery-powered node.")
                } else {
                    Text("The receiver is powered down to the lowest state this board can reach.")
                }
                if identUpdate {
                    Text("Nodes that can read this device's identity are told a \(precisionLabel(identPrecision)) area it is inside—never a more precise position than that.", comment: "Device setup: positioning footer. The placeholder is a cell size such as 611 m.")
                } else {
                    Text("The device does not put its location in the identity it advertises.")
                }
                if timeTrust {
                    Text("Fixes set the device's clock.")
                } else {
                    Text("Fixes never touch the clock, so a hand-set time is safe from a jammed or spoofed sky. Positions are unaffected.")
                }
            }
        }
    }

    private func precisionLabel(_ precision: Int64?) -> String {
        LocationPresentation.precisionLabel(precisionBytes: UInt8(clamping: precision ?? 0))
    }
}

// MARK: - Announcements

/// What the device says about itself unasked, on its own schedule.
struct AnnouncementsSection: View {
    @Binding var beaconInterval: Int64?
    let beaconChoices: MobileChoiceList?
    @Binding var advertInterval: Int64?
    let advertChoices: MobileChoiceList?
    @Binding var startupBeacon: Bool

    var body: some View {
        Section {
            Picker("Beacon", selection: $beaconInterval) {
                ChoiceListRows(list: beaconChoices, label: Self.intervalLabel)
            }
            Picker("Identity", selection: $advertInterval) {
                ChoiceListRows(list: advertChoices, label: Self.intervalLabel)
            }
            Toggle("Beacon at startup", isOn: $startupBeacon)
        } header: {
            Text("Announcements")
        } footer: {
            VStack(alignment: .leading, spacing: 4) {
                if (beaconInterval ?? 0) > 0 {
                    Text("A beacon carries no payload and collects the path back to this device as it travels, so it publishes a route for very little airtime.")
                } else {
                    Text("The device sends no beacons, so nothing refreshes the mesh's route back to it.")
                }
                if (advertInterval ?? 0) > 0 {
                    Text("An identity announcement carries this device's name, role, and capabilities, and reaches only the nodes that can hear it directly.")
                } else {
                    Text("The device announces its identity only when asked.")
                }
                if (beaconInterval ?? 0) > 0 || (advertInterval ?? 0) > 0 {
                    Text("Each interval is a minimum: periods run a little longer at random, so devices on the same schedule do not all transmit at once.")
                }
            }
        }
    }

    private static func intervalLabel(_ seconds: Int64) -> String {
        formattedAnnouncementInterval(UInt32(clamping: seconds))
    }
}

// MARK: - Apply status

/// How the last apply went, at the foot of the form, and what keeps the next
/// one from being allowed.
struct ApplyStatusSection: View {
    let result: MobileSetupResult?
    /// Settings holding a value the device cannot take that have no box of
    /// their own to say so under.
    let unshownProblems: [MobileSetupSetting]
    let applied: Bool

    var body: some View {
        if let text = result?.statusText {
            Section { Text(text).foregroundStyle(.red) }
        }

        if !unshownProblems.isEmpty {
            Section {
                ForEach(unshownProblems, id: \.self) { setting in
                    Text(setting.cannotBeSet).foregroundStyle(.red)
                }
            }
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
