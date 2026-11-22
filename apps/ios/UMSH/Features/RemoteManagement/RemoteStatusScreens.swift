import SwiftUI
import UMSHMobileCore

/// Read-only measurements from the sensors this device advertises.
struct RemoteSensorsScreen: View {
    let model: ManageDeviceModel

    private var reading: RemoteCategoryReading? { model.readings[.sensors] }

    var body: some View {
        Form {
            if model.properties(of: .sensors).contains(ulcpProperties.illuminance) {
                Section {
                    RemoteValueRow("Ambient light", value: lightReading)
                } footer: {
                    if let date = reading?.receivedAt[ulcpProperties.illuminance] {
                        Text(date, style: .relative)
                    }
                }
            }
            if model.properties(of: .sensors).contains(ulcpProperties.temperatures) {
                let temperature = RemoteTemperaturePresentation(reading: reading)
                Section {
                    ForEach(temperature.rows) { row in
                        RemoteValueRow(row.name, value: row.value)
                    }
                    if let state = temperature.state { Text(state).foregroundStyle(.secondary) }
                } header: {
                    Text("Temperature")
                } footer: {
                    if let problem = temperature.problem { Text(problem) }
                    if let date = temperature.sampledAt { Text(date, style: .relative) }
                }
            }
        }
        .remoteCategoryChrome(model: model, category: .sensors, title: "Sensors")
    }

    private var lightReading: String {
        let state = reading?.state(ulcpProperties.illuminance) ?? .notRead
        if let text = PropertyStateText.text(state) { return text }
        guard let millilux = reading?.properties.illuminanceMillilux else {
            return PropertyStateText.invalid
        }
        let lux = Double(millilux) / 1_000
        let digits = lux < 1 ? 3 : 2
        return lux.formatted(.number.precision(.fractionLength(digits))) + " lx"
    }
}

/// What a device's battery reports. Nothing here is settable—the readings
/// are the device describing itself.
struct RemotePowerScreen: View {
    let model: ManageDeviceModel

    private var reading: RemoteCategoryReading? { model.readings[.power] }

    var body: some View {
        Form {
            Section {
                if let battery = model.readings[.power]?.properties.battery {
                    if let percentage = battery.percentage {
                        RemoteValueRow("Charge", value: "\(percentage)%")
                    }
                    if let millivolts = battery.voltageMv {
                        RemoteValueRow(
                            "Voltage",
                            value: (Double(millivolts) / 1000)
                                .formatted(.number.precision(.fractionLength(2))) + " V"
                        )
                    }
                    if let state = battery.chargeState {
                        RemoteValueRow("State", value: RadioChargeState(state).label)
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
            diagnosticSection("Battery", fields: [
                (ulcpProperties.batteryCurrent, "Current"),
                (ulcpProperties.batteryRemainingCapacity, "Remaining capacity"),
                (ulcpProperties.batteryFullCapacity, "Full capacity"),
                (ulcpProperties.batteryDesignCapacity, "Design capacity"),
                (ulcpProperties.batteryPresent, "Battery present"),
            ], footer: "Positive current flows into the battery; negative current flows out. Full capacity is the gauge’s learned estimate; design capacity is its configured nominal capacity.")
            diagnosticSection("Charging", fields: [
                (ulcpProperties.batteryExtPowerPresent, "External power"),
                (ulcpProperties.batteryChargeVoltageRequest, "Requested charge voltage"),
                (ulcpProperties.batteryGaugeFull, "Gauge reports full"),
            ], footer: "The requested voltage is the gauge’s recommendation. The charger may use a different voltage. The gauge’s full indication is separate from the charger’s state.")
            diagnosticSection("Fuel gauge", fields: [
                (ulcpProperties.batteryGaugeInitialized, "Initialized"),
                (ulcpProperties.batteryGaugeSmoothing, "Smoothing"),
                (ulcpProperties.batteryGaugeFormat, "Format"),
                (ulcpProperties.batteryGaugeStatus, "Status flags"),
                (ulcpProperties.batteryGaugeOperationStatus, "Operation flags"),
            ], footer: "Initialized means the gauge is ready; it does not mean capacity learning is complete. Raw flags depend on the reported gauge format.")
            if let instant = reading?.batteryDiagnosticsAsOf {
                Section {
                    LabeledContent("Diagnostics read") {
                        Text(instant, style: .relative)
                            .foregroundStyle(.secondary)
                    }
                    .copyable(instant.formatted(date: .abbreviated, time: .standard))
                    Text("Refresh to request new diagnostics.")
                        .foregroundStyle(.secondary)
                }
            }
        }
        .remoteCategoryChrome(model: model, category: .power, title: "Power")
    }

    @ViewBuilder
    private func diagnosticSection(
        _ title: String, fields: [(UInt32, String)], footer: String
    ) -> some View {
        let visible = fields.filter { property, _ in
            // Only a missing property means unsupported. Empty successes and
            // temporary failures remain on screen and are fetched again.
            if reading?.values[property] != nil { return true }
            guard case let .refused(refusal) = reading?.state(property) else { return false }
            return refusal.reason != .noSuchProperty && refusal.status != nil
        }
        if !visible.isEmpty {
            Section {
                ForEach(visible, id: \.0) { property, label in
                    RemoteValueRow(label, value: diagnosticText(property))
                }
            } header: {
                Text(title)
            } footer: {
                Text(footer)
            }
        }
    }

    private func diagnosticText(_ property: UInt32) -> String {
        if case let .refused(refusal) = reading?.state(property) {
            return PropertyStateText.failed(status: refusal.status)
        }
        guard let bytes = reading?.values[property] else { return PropertyStateText.notRead }
        guard let value = try? inspectUlcpBatteryDiagnostic(propertyId: property, value: bytes)
        else { return PropertyStateText.invalid }
        switch value {
        case .unavailable:
            return PropertyStateText.unavailable
        case let .current(milliamps):
            return "\(milliamps > 0 ? "+" : "")\(milliamps) mA"
        case let .unsigned(value):
            if property == ulcpProperties.batteryGaugeStatus ||
                property == ulcpProperties.batteryGaugeOperationStatus {
                return "0x" + String(value, radix: 16, uppercase: true)
            }
            return "\(value) mAh"
        case let .boolean(value):
            return value ? "Yes" : "No"
        case let .voltage(millivolts):
            return (Double(millivolts) / 1000)
                .formatted(.number.precision(.fractionLength(3))) + " V"
        case .maximum:
            return "Maximum"
        case let .gaugeFormat(value):
            return value == 1 ? "BQ27220" : "Unknown (\(value))"
        }
    }
}

/// The device's receiver: whether it runs, and what it currently sees.
///
/// The fix is read-only—it is a measurement, and where a device *claims*
/// to be is on the Identity screen. How the device treats its receiver is a
/// decision, so those two are settings.
struct RemoteGnssScreen: View {
    let model: ManageDeviceModel
    @State private var draft: MobileGnssDraft?

    private var reading: RemoteCategoryReading? { model.readings[.gnss] }

    var body: some View {
        let review = model.review(draft)
        let problems = RemoteRowProblems(refusals: model.writeRefusals[.gnss] ?? [:], review: review)
        Form {
            Section("Receiver") {
                if let draft = Binding($draft) {
                    RemoteToggleField(
                        "Receiver enabled",
                        field: draft.enabled,
                        problem: problems[draft.wrappedValue.enabled.propertyId]
                    )
                } else {
                    RemoteReadOnlyToggle("Receiver enabled", isOn: nil)
                }
            }

            Section {
                if let gnss = reading?.properties.gnss {
                    RemoteValueRow("Fix", value: label(for: gnss.fix))
                    if let latitude = gnss.latitudeDeg, let longitude = gnss.longitudeDeg {
                        RemoteValueRow(
                            "Position",
                            value: "\(coordinate(latitude)), \(coordinate(longitude))"
                        )
                    }
                    if let altitude = gnss.altitudeM {
                        RemoteValueRow("Altitude", value: "\(altitude) m")
                    }
                    RemoteValueRow("Satellites used", value: "\(gnss.satellitesUsed)")
                    if let inView = gnss.satellitesInView {
                        RemoteValueRow("Satellites in view", value: "\(inView)")
                    }
                } else {
                    RemoteEmptyReading()
                }
            } header: {
                Text("Current fix")
            } footer: {
                RemoteReadingFooter(reading: reading, isBusy: model.isBusy)
            }
        }
        .remoteCategoryChrome(
            model: model,
            category: .gnss,
            title: "GNSS",
            apply: { await model.applyAndRebuild($draft) },
            review: review
        )
        .draft($draft, from: model, revision: reading?.revision)
    }

    private func label(for fix: UlcpFixKind) -> String {
        switch fix {
        case .none: "Searching"
        case .twoD: "2D"
        case .threeD: "3D"
        case .unknown: "Fix"
        }
    }

    private func coordinate(_ degrees: Double) -> String {
        degrees.formatted(.number.precision(.fractionLength(5))) + "°"
    }
}

/// The device's wall clock: what time it holds, where it is meant to be,
/// how it writes the hour, and whether the receiver may set the clock.
///
/// The clock itself is live state—set from this phone the moment the
/// button is tapped, never part of Apply, and never persisted by the
/// device, which has no bound on how long it spends powered off. The time
/// zone, the clock format, and the receiver's say over the clock are
/// settings, and go through Apply like any other.
struct RemoteTimeScreen: View {
    let model: ManageDeviceModel
    @State private var draft: MobileTimeDraft?

    private var reading: RemoteCategoryReading? { model.readings[.time] }

    var body: some View {
        let review = model.review(draft)
        let problems = RemoteRowProblems(refusals: model.writeRefusals[.time] ?? [:], review: review)
        Form {
            if let uptime {
                Section {
                    // Uptime advances at exactly a second per second, so
                    // extrapolating from the read is as true as the read
                    // was—and a stopped counter would read as a device
                    // that had just rebooted.
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        RemoteValueRow(
                            "Uptime",
                            value: formattedUptime(elapsedUptime(uptime, asOf: context.date))
                        )
                    }
                } header: {
                    Text("Uptime")
                } footer: {
                    Text("How long since the device last restarted.")
                }
            }

            Section {
                if let clock {
                    if let date = clock.date {
                        // Re-render each second so the clock reads as one,
                        // not as a stopped reading from whenever the screen
                        // was refreshed.
                        TimelineView(.periodic(from: .now, by: 1)) { context in
                            RemoteValueRow(
                                "Device time",
                                value: date.addingTimeInterval(
                                    context.date.timeIntervalSince(clock.readAt)
                                )
                                .formatted(date: .abbreviated, time: .standard)
                            )
                        }
                        if let drift = clock.driftSummary() {
                            RemoteValueRow("Drift", value: drift)
                        }
                    } else {
                        RemoteValueRow("Device time", value: "Not set")
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
                if let draft = Binding($draft), draft.wrappedValue.tzRule.known {
                    NavigationLink {
                        RemoteTimeZonePicker(rule: draft.tzRule.text)
                    } label: {
                        LabeledContent {
                            Text(formattedTimeZoneRule(draft.wrappedValue.tzRule.text))
                        } label: {
                            RemoteFieldTitle(
                                "Time zone",
                                problem: problems[draft.wrappedValue.tzRule.propertyId]
                            )
                        }
                    }
                    if draft.wrappedValue.tzRule.text != phoneTimeZoneRule {
                        Button("Use This iPhone's Time Zone") {
                            draft.wrappedValue.tzRule.text = phoneTimeZoneRule
                        }
                    }
                } else {
                    RemoteNotRead(title: "Time zone")
                        .labeledContentStyle(SettingsFieldStyle())
                }
                if let draft = Binding($draft) {
                    RemoteToggleField(
                        "24-hour clock",
                        field: draft.time24h,
                        problem: problems[draft.wrappedValue.time24h.propertyId]
                    )
                } else {
                    RemoteReadOnlyToggle("24-hour clock", isOn: nil)
                }
            } header: {
                Text("Time zone")
            } footer: {
                Text("Where the device is meant to be, for anything it dates locally.")
            }

            if model.card?.supportsGnss == true {
                Section {
                    if let draft = Binding($draft) {
                        RemoteToggleField(
                            "Trust the receiver's clock",
                            field: draft.timeTrust,
                            problem: problems[draft.wrappedValue.timeTrust.propertyId]
                        )
                    } else {
                        RemoteReadOnlyToggle("Trust the receiver's clock", isOn: nil)
                    }
                } footer: {
                    Text("On, a GNSS fix sets the device's clock by itself.")
                }
            }
        }
        .remoteCategoryChrome(
            model: model,
            category: .time,
            title: "Time",
            apply: { await model.applyAndRebuild($draft) },
            review: review
        )
        .draft($draft, from: model, revision: reading?.revision)
    }

    /// Uptime as of the last read, carried with the instant it was
    /// learned so the row can keep counting from there.
    private var uptime: (read: UInt32, asOf: Date)? {
        guard let reading, let seconds = reading.properties.uptimeSeconds,
              let asOf = reading.receivedAt[ulcpProperties.uptime]
        else { return nil }
        return (seconds, asOf)
    }

    /// The reading carried forward to now. Clamped at both ends: a phone
    /// clock that jumps backwards cannot push the count below what was
    /// read, and the sum saturates rather than wrapping into a device
    /// that looks freshly rebooted.
    private func elapsedUptime(_ uptime: (read: UInt32, asOf: Date), asOf now: Date) -> UInt32 {
        let since = max(0, now.timeIntervalSince(uptime.asOf))
        return UInt32(clamping: UInt64(uptime.read) + UInt64(since))
    }

    /// The clock as of the last read, in the shape the companion screen
    /// already presents one.
    private var clock: RadioClock? {
        guard let reading, let time = reading.properties.time,
              let asOf = reading.receivedAt[ulcpProperties.time]
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
        await model.setClockNow()
    }
}

/// Every zone this iPhone knows, for a device that belongs somewhere other
/// than where the phone is. Choosing one is an edit, applied with the rest
/// of the Time screen.
struct RemoteTimeZonePicker: View {
    @Binding var rule: String
    @Environment(\.dismiss) private var dismiss
    @State private var zones: [DeviceTimeZone]?
    @State private var query = ""

    var body: some View {
        List {
            if let zones {
                let shown = query.isEmpty ? zones : zones.filter { $0.matches(query) }
                ForEach(shown) { zone in
                    Button {
                        rule = zone.rule
                        dismiss()
                    } label: {
                        row(zone)
                    }
                    .buttonStyle(.plain)
                }
                if shown.isEmpty {
                    Text("None").foregroundStyle(.secondary)
                }
            } else {
                ProgressView()
                    .frame(maxWidth: .infinity)
            }
        }
        .searchable(text: $query, prompt: "Zone or city")
        .navigationTitle("Time Zone")
        .navigationBarTitleDisplayMode(.inline)
        .task {
            zones = await Task.detached(priority: .userInitiated) {
                DeviceTimeZone.all()
            }.value
        }
    }

    private func row(_ zone: DeviceTimeZone) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(zone.name)
                if !zone.cities.isEmpty {
                    Text(zone.cities.joined(separator: ", "))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer()
            Text(formattedUTCOffset(zone.offsetMinutes))
                .foregroundStyle(.secondary)
                .monospacedDigit()
            Image(systemName: "checkmark")
                .foregroundStyle(.tint)
                .opacity(zone.rule == rule ? 1 : 0)
                .accessibilityHidden(zone.rule != rule)
        }
        .contentShape(Rectangle())
        .accessibilityAddTraits(zone.rule == rule ? .isSelected : [])
    }
}

/// Traffic accumulated by the device since boot or the last explicit reset.
/// Duty cycle is shown beside the tallies but remains a rolling regulatory
/// measurement, so Reset Counters never touches it.
struct RemoteStatisticsScreen: View {
    let model: ManageDeviceModel
    @State private var confirmsReset = false

    private var reading: RemoteCategoryReading? { model.readings[.statistics] }
    private var stats: UlcpDevicePropertiesRecord {
        reading?.properties ?? .empty
    }

    /// Whether Reset Counters would zero anything.
    private var hasCounters: Bool {
        reading?.record.canResetCounters ?? false
    }

    private var hasForwarding: Bool {
        stats.statForwarded != nil
            || stats.statForwardDropped != nil
            || stats.statForwardCancelled != nil
    }

    private var hasMeshCore: Bool {
        stats.statMeshcoreSeen != nil
            || stats.statMeshcoreForwardedRouted != nil
            || stats.statMeshcoreForwardedFlood != nil
            || stats.statMeshcoreDeclined != nil
    }

    var body: some View {
        Form {
            Section("Transmit") {
                if let value = stats.statTxPackets {
                    RemoteValueRow("Packets", value: value.formatted())
                }
                if let value = stats.statTxChannelBusy {
                    RemoteValueRow("Deferred—channel busy", value: value.formatted())
                }
                if let value = stats.dutyCycleNow {
                    RemoteValueRow("Duty cycle", value: dutyPercent(value))
                }
                if stats.statTxPackets == nil,
                   stats.statTxChannelBusy == nil,
                   stats.dutyCycleNow == nil {
                    RemoteEmptyReading()
                }
            }

            Section("Receive") {
                if let value = stats.statRxPackets {
                    RemoteValueRow("UMSH packets", value: value.formatted())
                }
                if let value = stats.statRxBadCrc {
                    RemoteValueRow("Bad CRC", value: value.formatted())
                }
                if let value = stats.statRxNonUmsh {
                    RemoteValueRow("Non-UMSH packets", value: value.formatted())
                }
                if let value = stats.statRxAccepted {
                    RemoteValueRow("For this node", value: value.formatted())
                }
                if let value = stats.rxDutyCycle {
                    RemoteValueRow(
                        String(localized: "Airtime heard", comment: "Statistics row: the share of the past five minutes other transmitters occupied the channel."),
                        value: dutyPercent(value)
                    )
                }
                if let value = stats.repeatersHeard {
                    RemoteValueRow(
                        String(localized: "Repeaters heard", comment: "Statistics row: how many repeaters the device heard in the past hour."),
                        value: value.formatted()
                    )
                }
            }

            if hasForwarding {
                Section("Forwarding") {
                    if let value = stats.statForwarded {
                        RemoteValueRow("Forwarded", value: value.formatted())
                    }
                    if let value = stats.statForwardDropped {
                        RemoteValueRow("Policy dropped", value: value.formatted())
                    }
                    if let value = stats.statForwardCancelled {
                        RemoteValueRow("Cancelled", value: value.formatted())
                    }
                }
            }

            if hasMeshCore {
                Section("MeshCore") {
                    if let value = stats.statMeshcoreSeen {
                        RemoteValueRow("Seen", value: value.formatted())
                    }
                    if let value = stats.statMeshcoreForwardedRouted {
                        RemoteValueRow("Forwarded Routed", value: value.formatted())
                    }
                    if let value = stats.statMeshcoreForwardedFlood {
                        RemoteValueRow("Forwarded Flood", value: value.formatted())
                    }
                    if let value = stats.statMeshcoreDeclined {
                        RemoteValueRow("Declined", value: value.formatted())
                    }
                }
            }

            Section {
                if let value = stats.statRadioResets {
                    RemoteValueRow(
                        String(
                            localized: "Radio resets",
                            comment: "Statistics row: how many times the device reset its radio chip. A noun."
                        ),
                        value: value.formatted()
                    )
                }
                if let uptime = currentUptime {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        RemoteValueRow(
                            "Uptime",
                            value: formattedUptime(elapsedUptime(uptime, asOf: context.date))
                        )
                    }
                }
                Button("Reset Counters…", role: .destructive) {
                    confirmsReset = true
                }
                .disabled(!hasCounters)
            } footer: {
                RemoteReadingFooter(reading: reading, isBusy: model.isBusy)
            }
        }
        .remoteCategoryChrome(model: model, category: .statistics, title: "Statistics")
        .confirmationDialog(
            "Reset All Counters?",
            isPresented: $confirmsReset,
            titleVisibility: .visible
        ) {
            Button("Reset Counters", role: .destructive) {
                Task { await resetCounters() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Duty cycle and uptime are not reset.")
        }
    }

    private var currentUptime: (read: UInt32, asOf: Date)? {
        guard let reading, let seconds = stats.uptimeSeconds,
              let asOf = reading.receivedAt[ulcpProperties.uptime] else {
            return nil
        }
        return (seconds, asOf)
    }

    private func elapsedUptime(_ uptime: (read: UInt32, asOf: Date), asOf now: Date) -> UInt32 {
        let since = max(0, now.timeIntervalSince(uptime.asOf))
        return UInt32(clamping: UInt64(uptime.read) + UInt64(since))
    }

    private func dutyPercent(_ raw: UInt16) -> String {
        (Double(raw) * 100 / Double(UInt16.max))
            .formatted(.number.precision(.fractionLength(2))) + "%"
    }

    private func resetCounters() async {
        await model.resetCounters()
    }
}

// MARK: - Shared pieces

/// A setting shown as the device reports it, with no way to change it here.
///
