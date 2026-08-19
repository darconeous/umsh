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

    var body: some View {
        Form {
            Section("Receiver") {
                if edits.enabled.isKnown {
                    Toggle(
                        "Receiver enabled",
                        isOn: $edits.enabled.edited.replacingNil(with: false)
                    )
                } else {
                    RemoteReadOnlyToggle("Receiver enabled", isOn: nil)
                }
                if edits.timeTrust.isKnown {
                    Toggle(
                        "Trust the receiver's clock",
                        isOn: $edits.timeTrust.edited.replacingNil(with: false)
                    )
                } else {
                    RemoteReadOnlyToggle("Trust the receiver's clock", isOn: nil)
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
        .onChange(of: reading?.asOf) { edits = Edits(reading) }
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

    /// The two settings on this screen. The fix is not among them: it is
    /// what the receiver reports, not something to ask it for.
    private struct Edits {
        var enabled = RemoteField<Bool>(0, nil)
        var timeTrust = RemoteField<Bool>(0, nil)
        var isEmpty = true
        /// What the device last said, in full.
        var held = UlcpDevicePropertiesRecord.empty

        init() {}

        init(_ reading: RemoteCategoryReading?) {
            let id = ulcpProperties
            held = reading?.properties ?? UlcpDevicePropertiesRecord.empty
            enabled = RemoteField(id.gnssEnabled, held.gnssEnabled)
            timeTrust = RemoteField(id.gnssTimeTrust, held.gnssTimeTrust)
            isEmpty = reading == nil
        }

        var dirty: Set<UInt32> {
            var dirty: Set<UInt32> = []
            if enabled.isDirty { dirty.insert(enabled.property) }
            if timeTrust.isDirty { dirty.insert(timeTrust.property) }
            return dirty
        }

        var desired: UlcpDevicePropertiesRecord {
            // Based on what the device last reported, not on nothing: a
            // whole-write group can reach across screens, and its members
            // over on another one still have to be stated. Only the dirty
            // set and its groups are written, so carrying the rest here
            // cannot write anything stale back.
            var desired = held
            desired.gnssEnabled = enabled.value
            desired.gnssTimeTrust = timeTrust.value
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
