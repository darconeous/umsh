import SwiftUI
import UMSHMobileCore

/// What a device's battery reports. Nothing here is settable — the readings
/// are the device describing itself.
struct RemotePowerScreen: View {
    let model: ManageDeviceModel

    var body: some View {
        Form {
            Section {
                if let battery = model.readings[.power]?.properties.battery {
                    if let percentage = battery.percentage {
                        LabeledContent("Charge", value: "\(percentage)%")
                    }
                    if let millivolts = battery.voltageMv {
                        LabeledContent(
                            "Voltage",
                            value: (Double(millivolts) / 1000)
                                .formatted(.number.precision(.fractionLength(2))) + " V"
                        )
                    }
                    if let state = battery.chargeState {
                        LabeledContent("State", value: RadioChargeState(state).label)
                    }
                    if battery.percentage == nil, battery.voltageMv == nil,
                       battery.chargeState == nil {
                        Text("The device reports a battery but no readings from it.")
                            .foregroundStyle(.secondary)
                    }
                } else {
                    RemoteEmptyReading()
                }
            } footer: {
                RemoteReadingFooter(reading: model.readings[.power], isBusy: model.isBusy)
            }
            RemoteProblemSection(model: model)
        }
        .remoteCategoryChrome(model: model, category: .power, title: "Power")
    }
}

/// The device's receiver: whether it runs, and what it currently sees.
///
/// The fix is read-only — it is a measurement, and where a device *claims*
/// to be is on the Identity screen. How the device treats its receiver is a
/// decision, so those two are settings.
struct RemoteGnssScreen: View {
    let model: ManageDeviceModel
    @State private var edits = Edits()

    private var reading: RemoteCategoryReading? { model.readings[.gnss] }
    private var problems: [UInt32: String] { model.writeRefusals[.gnss] ?? [:] }

    var body: some View {
        Form {
            Section("Receiver") {
                if edits.enabled.isKnown {
                    Toggle(isOn: $edits.enabled.edited.replacingNil(with: false)) {
                        RemoteFieldTitle(
                            "Receiver enabled",
                            problem: problems[edits.enabled.property]
                        )
                    }
                } else {
                    RemoteReadOnlyToggle("Receiver enabled", isOn: nil)
                }
            }

            Section {
                if let gnss = reading?.properties.gnss {
                    LabeledContent("Fix", value: label(for: gnss.fix))
                    if let latitude = gnss.latitudeDeg, let longitude = gnss.longitudeDeg {
                        LabeledContent(
                            "Position",
                            value: "\(coordinate(latitude)), \(coordinate(longitude))"
                        )
                    }
                    if let altitude = gnss.altitudeM {
                        LabeledContent("Altitude", value: "\(altitude) m")
                    }
                    LabeledContent("Satellites used", value: "\(gnss.satellitesUsed)")
                    if let inView = gnss.satellitesInView {
                        LabeledContent("Satellites in view", value: "\(inView)")
                    }
                } else {
                    RemoteEmptyReading()
                }
            } header: {
                Text("Current fix")
            } footer: {
                RemoteReadingFooter(reading: reading, isBusy: model.isBusy)
            }
            RemoteProblemSection(model: model)
        }
        .remoteCategoryChrome(
            model: model,
            category: .gnss,
            title: "GNSS",
            apply: { await apply() },
            hasEdits: !edits.dirty.isEmpty
        )
        .onChange(of: reading?.asOf) { edits = Edits(reading, preserving: edits) }
        .onAppear { if edits.isEmpty { edits = Edits(reading) } }
    }

    private func apply() async {
        // Rebuilt from what the device answered — but only if it answered.
        // A write that never left the phone leaves these fields as the only
        // copy of what the operator asked for.
        if await model.apply(.gnss, desired: edits.desired, dirty: edits.dirty) {
            edits = Edits(model.readings[.gnss])
        }
    }

    /// The one setting on this screen. The fix is not among them: it is
    /// what the receiver reports, not something to ask it for. Whether the
    /// receiver may set the clock lives on the Time screen, with the clock.
    private struct Edits {
        var enabled = RemoteField<Bool>(0, nil)
        var isEmpty = true
        /// What the device last said, in full.
        var held = UlcpDevicePropertiesRecord.empty

        init() {}

        init(_ reading: RemoteCategoryReading?) {
            let id = ulcpProperties
            held = reading?.properties ?? UlcpDevicePropertiesRecord.empty
            enabled = RemoteField(id.gnssEnabled, held.gnssEnabled)
            isEmpty = reading == nil
        }

        /// The new reading as the baseline, with the operator's standing
        /// edit carried over — see ``RemoteField/preserving(_:)``.
        init(_ reading: RemoteCategoryReading?, preserving old: Edits) {
            self.init(reading)
            guard !old.isEmpty else { return }
            enabled = enabled.preserving(old.enabled)
        }

        var dirty: Set<UInt32> {
            var dirty: Set<UInt32> = []
            if enabled.isDirty { dirty.insert(enabled.property) }
            return dirty
        }

        var desired: UlcpDevicePropertiesRecord {
            // Only the dirty set is written; the rest of the record is
            // carried for completeness and never reaches the air.
            var desired = held
            desired.gnssEnabled = enabled.value
            return desired
        }
    }

    private func label(for fix: UlcpFixKind) -> String {
        switch fix {
        case .none: "Searching"
        case .twoD: "2D"
        case .threeD: "3D"
        }
    }

    private func coordinate(_ degrees: Double) -> String {
        degrees.formatted(.number.precision(.fractionLength(5))) + "°"
    }
}

/// The device's wall clock: what time it holds, where it is meant to be,
/// and whether the receiver may set the clock.
///
/// The clock itself is live state — set from this phone the moment the
/// button is tapped, never part of Apply, and never persisted by the
/// device, which has no bound on how long it spends powered off. The time
/// zone and the receiver's say over the clock are settings, and go through
/// Apply like any other.
struct RemoteTimeScreen: View {
    let model: ManageDeviceModel
    @State private var edits = Edits()

    private var reading: RemoteCategoryReading? { model.readings[.time] }
    private var problems: [UInt32: String] { model.writeRefusals[.time] ?? [:] }

    var body: some View {
        Form {
            Section {
                if let clock {
                    if let date = clock.date {
                        // Re-render each second so the clock reads as one,
                        // not as a stopped reading from whenever the screen
                        // was refreshed.
                        TimelineView(.periodic(from: .now, by: 1)) { context in
                            LabeledContent(
                                "Device time",
                                value: date.addingTimeInterval(
                                    context.date.timeIntervalSince(clock.readAt)
                                )
                                .formatted(date: .abbreviated, time: .standard)
                            )
                        }
                        if let drift = clock.driftSummary() {
                            LabeledContent("Drift", value: drift)
                        }
                    } else {
                        LabeledContent("Device time", value: "Not set")
                    }
                    Button("Set From iPhone") {
                        Task { await setFromPhone() }
                    }
                } else {
                    RemoteEmptyReading()
                }
            } header: {
                Text("Clock")
            } footer: {
                RemoteReadingFooter(reading: reading, isBusy: model.isBusy)
            }

            Section {
                RemotePicker(
                    "Time zone",
                    selection: $edits.tzOffset.edited,
                    problem: problems[edits.tzOffset.property]
                ) {
                    ForEach(deviceTimeZoneOffsets, id: \.self) { minutes in
                        Text(formattedUTCOffset(minutes)).tag(minutes)
                    }
                }
                if edits.tzOffset.isKnown, edits.tzOffset.value != phoneUTCOffsetMinutes {
                    Button("Use This iPhone's Time Zone") {
                        edits.tzOffset.edited = phoneUTCOffsetMinutes
                    }
                }
            } header: {
                Text("Time zone")
            } footer: {
                Text("Where the device is meant to be, for anything it dates locally.")
            }

            if model.card?.supportsGnss == true {
                Section {
                    if edits.timeTrust.isKnown {
                        Toggle(isOn: $edits.timeTrust.edited.replacingNil(with: false)) {
                            RemoteFieldTitle(
                                "Trust the receiver's clock",
                                problem: problems[edits.timeTrust.property]
                            )
                        }
                    } else {
                        RemoteReadOnlyToggle("Trust the receiver's clock", isOn: nil)
                    }
                } footer: {
                    Text("On, a GNSS fix sets the device's clock by itself.")
                }
            }
            RemoteProblemSection(model: model)
        }
        .remoteCategoryChrome(
            model: model,
            category: .time,
            title: "Time",
            apply: { await apply() },
            hasEdits: !edits.dirty.isEmpty
        )
        .onChange(of: reading?.asOf) { edits = Edits(reading, preserving: edits) }
        .onAppear { if edits.isEmpty { edits = Edits(reading) } }
    }

    /// The clock as of the last read, in the shape the companion screen
    /// already presents one.
    private var clock: RadioClock? {
        guard let reading, let time = reading.properties.time, let asOf = reading.asOf
        else { return nil }
        return RadioClock(
            date: time.epochSeconds.map { Date(timeIntervalSince1970: TimeInterval($0)) },
            readAt: asOf
        )
    }

    /// Write the phone's own clock to the device, immediately.
    ///
    /// Not an edit awaiting Apply: a clock staged in a form is wrong by
    /// the time it is applied, by however long the operator took.
    private func setFromPhone() async {
        var desired = reading?.properties ?? .empty
        desired.time = UlcpTimeRecord(
            epochSeconds: UInt32(clamping: Int(Date.now.timeIntervalSince1970))
        )
        await model.apply(.time, desired: desired, dirty: [ulcpProperties.time])
    }

    private func apply() async {
        // Only rebuilt when the device answered: see RemoteGnssScreen.
        if await model.apply(.time, desired: edits.desired, dirty: edits.dirty) {
            edits = Edits(model.readings[.time])
        }
    }

    /// The two settings here. The clock is deliberately not among them —
    /// see the screen comment.
    private struct Edits {
        var tzOffset = RemoteField<Int16>(0, nil)
        var timeTrust = RemoteField<Bool>(0, nil)
        var isEmpty = true
        /// What the device last said, in full.
        var held = UlcpDevicePropertiesRecord.empty

        init() {}

        init(_ reading: RemoteCategoryReading?) {
            let id = ulcpProperties
            held = reading?.properties ?? UlcpDevicePropertiesRecord.empty
            tzOffset = RemoteField(id.tzOffset, held.tzOffsetMin)
            timeTrust = RemoteField(id.gnssTimeTrust, held.gnssTimeTrust)
            isEmpty = reading == nil
        }

        /// The new reading as the baseline, with the operator's standing
        /// edits carried over — see ``RemoteField/preserving(_:)``.
        init(_ reading: RemoteCategoryReading?, preserving old: Edits) {
            self.init(reading)
            guard !old.isEmpty else { return }
            tzOffset = tzOffset.preserving(old.tzOffset)
            timeTrust = timeTrust.preserving(old.timeTrust)
        }

        var dirty: Set<UInt32> {
            var dirty: Set<UInt32> = []
            if tzOffset.isDirty { dirty.insert(tzOffset.property) }
            if timeTrust.isDirty { dirty.insert(timeTrust.property) }
            return dirty
        }

        var desired: UlcpDevicePropertiesRecord {
            // Only the dirty set is written; the rest of the record is
            // carried for completeness and never reaches the air.
            var desired = held
            desired.tzOffsetMin = tzOffset.value
            desired.gnssTimeTrust = timeTrust.value
            return desired
        }
    }
}

// MARK: - Shared pieces

/// A setting shown as the device reports it, with no way to change it here.
///
/// A disabled `Toggle` rather than a yes/no label, so a control that *is*
/// editable elsewhere reads the same in both places.
struct RemoteReadOnlyToggle: View {
    let title: String
    let isOn: Bool?

    init(_ title: String, isOn: Bool?) {
        self.title = title
        self.isOn = isOn
    }

    var body: some View {
        if let isOn {
            Toggle(title, isOn: .constant(isOn)).disabled(true)
        } else {
            LabeledContent(title, value: "Not read")
        }
    }
}

/// What a screen shows before anything has been read from the device. The
/// footer below it is where Refresh gets mentioned.
struct RemoteEmptyReading: View {
    var body: some View {
        Text("Not read").foregroundStyle(.secondary)
    }
}

/// The last failure, where every category screen puts it.
struct RemoteProblemSection: View {
    let model: ManageDeviceModel

    var body: some View {
        if let problem = model.problem {
            Section { Text(problem).foregroundStyle(.red) }
        }
    }
}
