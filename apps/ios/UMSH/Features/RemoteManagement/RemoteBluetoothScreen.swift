import SwiftUI
import UMSHMobileCore

/// The device's Bluetooth: whether it can be reached over it, how many
/// hosts are paired, and the two things worth doing to that list.
///
/// The one management screen whose controls can act on the link carrying
/// them. Switching Bluetooth off drops the attached host, and forgetting
/// every pairing drops it and locks it out until someone pairs again — so
/// what a control *means* here depends on how this device was reached, and
/// the copy says so rather than leaving the operator to find out.
struct RemoteBluetoothScreen: View {
    let model: ManageDeviceModel
    @State private var edits = Edits()
    @State private var isConfirmingPairing = false
    @State private var isConfirmingClear = false

    private var reading: RemoteCategoryReading? { model.readings[.bluetooth] }
    private var problems: [UInt32: String] { model.writeRefusals[.bluetooth] ?? [:] }

    /// Whether this phone is talking to the device over the Bluetooth this
    /// screen configures. On the mesh it is not: the device is reached
    /// through the radio in the operator's pocket, and its Bluetooth is
    /// just another setting.
    private var overThisLink: Bool { model.link != .mesh }

    var body: some View {
        Form {
            Section {
                if edits.enabled.isKnown {
                    Toggle(isOn: $edits.enabled.edited.replacingNil(with: false)) {
                        RemoteFieldTitle(
                            "Bluetooth enabled",
                            problem: problems[edits.enabled.property]
                        )
                    }
                } else {
                    RemoteReadOnlyToggle("Bluetooth enabled", isOn: nil)
                }
            } footer: {
                Text(
                    overThisLink
                        ? "Turning Bluetooth off disconnects this phone. The device keeps its pairings, but you will need another way to reach it to turn Bluetooth back on."
                        : "Turning Bluetooth off makes the device unreachable by phone. It keeps its pairings and stays on the mesh."
                )
            }

            Section {
                if model.supportsBluetoothPairing {
                    if let count = reading?.properties.bleBondCount {
                        LabeledContent("Paired phones", value: "\(count)")
                    } else {
                        LabeledContent("Paired phones", value: "Not read")
                    }
                }
                LabeledContent("Connection", value: connectionSummary)
            } header: {
                Text("Status")
            } footer: {
                RemoteReadingFooter(reading: reading, isBusy: model.isBusy)
            }

            if model.supportsBluetoothPairing {
                Section {
                    Button("Start Pairing Mode…") { isConfirmingPairing = true }
                    Button("Clear Pairings…", role: .destructive) { isConfirmingClear = true }
                } footer: {
                    Text(
                        "Pairing mode lets another phone pair without pressing anything on the device. Clearing forgets every paired phone and the pairing PIN."
                    )
                }
            }

            RemoteProblemSection(model: model)
        }
        .confirmationDialog(
            "Start pairing mode?",
            isPresented: $isConfirmingPairing,
            titleVisibility: .visible
        ) {
            Button("Start Pairing Mode") { Task { await model.startBluetoothPairing() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(
                "For about half a minute, any phone nearby can pair with this device. A phone that pairs can manage it and read everything it holds."
            )
        }
        .confirmationDialog(
            "Clear every pairing?",
            isPresented: $isConfirmingClear,
            titleVisibility: .visible
        ) {
            Button("Clear Pairings", role: .destructive) {
                Task { await model.clearBluetoothPairings() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(clearWarning)
        }
        .remoteCategoryChrome(
            model: model,
            category: .bluetooth,
            title: "Bluetooth",
            apply: { await apply() },
            hasEdits: !edits.dirty.isEmpty,
            applyWarning: edits.disablesBluetooth ? disableWarning : nil
        )
        .onChange(of: reading?.asOf) { edits = Edits(reading, preserving: edits) }
        .onAppear { if edits.isEmpty { edits = Edits(reading) } }
    }

    /// Who is on the device's Bluetooth right now.
    ///
    /// Over the mesh this is the interesting row on the screen — it is the
    /// only way to ask whether someone else is managing the device. Over
    /// Bluetooth it can only ever say "attached", because the phone
    /// reading it is the attachment, so the copy says so instead of
    /// reporting the phone back to itself as news.
    private var connectionSummary: String {
        guard let state = reading?.properties.bleLink else { return "Not read" }
        switch state {
        case 0: return "Nobody connected"
        case 1: return "A phone is connected"
        case 2: return overThisLink ? "This phone" : "A phone is managing this device"
        default: return "Unknown"
        }
    }

    /// What clearing costs, which is not the same question on every link.
    private var clearWarning: String {
        let paired = reading?.properties.bleBondCount
        let subject = switch paired {
        case .some(let count) where count == 1: "The one phone paired with this device"
        case .some(let count) where count > 1: "All \(count) phones paired with this device"
        default: "Every phone paired with this device"
        }
        return overThisLink
            ? "\(subject), including this one, will be forgotten. The device then opens a pairing window so you can pair again."
            : "\(subject) will be forgotten. The device then opens a pairing window so someone can pair again."
    }

    /// The stranding warning, in the terms of the link it would strand.
    ///
    /// Modeled on the Radio screen's: a change that can put a device out of
    /// reach is confirmed once, on every route into Apply.
    private var disableWarning: (title: String, message: String) {
        switch model.link {
        case .companion:
            (
                title: "Disconnect This Radio",
                message: """
                    Turning Bluetooth off disconnects the radio this phone is \
                    using, and the mesh goes with it. The only way back is the \
                    controls on the device itself.
                    """
            )
        case .administrative:
            (
                title: "End This Session",
                message: """
                    Turning Bluetooth off disconnects the device and ends this \
                    setup session. The only way back is the controls on the \
                    device itself.
                    """
            )
        case .mesh:
            (
                title: "Turn Bluetooth Off",
                message: """
                    The device stays on the mesh, but no phone will be able to \
                    connect to it directly until Bluetooth is turned back on.
                    """
            )
        }
    }

    private func apply() async {
        // Rebuilt from what the device answered — but only if it answered.
        // A write that never left the phone leaves these fields as the only
        // copy of what the operator asked for.
        if await model.apply(.bluetooth, desired: edits.desired, dirty: edits.dirty) {
            edits = Edits(model.readings[.bluetooth])
        }
    }

    /// The one setting on this screen. The pairing count is a reading, and
    /// the two actions are commands — neither is part of Apply.
    private struct Edits {
        var enabled = RemoteField<Bool>(0, nil)
        var isEmpty = true
        /// What the device last said, in full.
        var held = UlcpDevicePropertiesRecord.empty

        init() {}

        init(_ reading: RemoteCategoryReading?) {
            let id = ulcpProperties
            held = reading?.properties ?? UlcpDevicePropertiesRecord.empty
            enabled = RemoteField(id.bleEnabled, held.bleEnabled)
            isEmpty = reading == nil
        }

        /// The new reading as the baseline, with the operator's standing
        /// edit carried over — see ``RemoteField/preserving(_:)``.
        init(_ reading: RemoteCategoryReading?, preserving old: Edits) {
            self.init(reading)
            guard !old.isEmpty else { return }
            enabled = enabled.preserving(old.enabled)
        }

        /// Whether Apply would turn Bluetooth off. Only an edit counts: a
        /// device already unreachable over Bluetooth is not being made so.
        var disablesBluetooth: Bool { enabled.isDirty && enabled.value == false }

        var dirty: Set<UInt32> {
            var dirty: Set<UInt32> = []
            if enabled.isDirty { dirty.insert(enabled.property) }
            return dirty
        }

        var desired: UlcpDevicePropertiesRecord {
            // Only the dirty set is written; the rest of the record is
            // carried for completeness and never reaches the air.
            var desired = held
            desired.bleEnabled = enabled.value
            return desired
        }
    }
}
