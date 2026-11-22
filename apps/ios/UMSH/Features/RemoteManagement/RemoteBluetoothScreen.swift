import SwiftUI
import UMSHMobileCore

/// The device's Bluetooth: whether it can be reached over it, how many
/// hosts are paired, and the two things worth doing to that list.
///
/// The one management screen whose controls can act on the link carrying
/// them. Switching Bluetooth off drops the attached host, and forgetting
/// every pairing drops it and locks it out until someone pairs again—so
/// what a control *means* here depends on how this device was reached, and
/// the copy says so rather than leaving the operator to find out.
struct RemoteBluetoothScreen: View {
    let model: ManageDeviceModel
    @State private var draft: MobileBluetoothDraft?
    @State private var isConfirmingClear = false

    private var reading: RemoteCategoryReading? { model.readings[.bluetooth] }

    /// Whether this phone is talking to the device over the Bluetooth this
    /// screen configures. On the mesh it is not: the device is reached
    /// through the radio in the operator's pocket, and its Bluetooth is
    /// just another setting.
    private var overThisLink: Bool { model.usesBluetooth }

    var body: some View {
        let review = model.review(draft)
        let problems = RemoteRowProblems(refusals: model.writeRefusals[.bluetooth] ?? [:], review: review)
        Form {
            Section {
                if let draft = Binding($draft) {
                    RemoteToggleField(
                        "Bluetooth enabled",
                        field: draft.enabled,
                        problem: problems[draft.wrappedValue.enabled.propertyId]
                    )
                } else {
                    RemoteReadOnlyToggle("Bluetooth enabled", isOn: nil)
                }
            } footer: {
                Text(
                    overThisLink
                        ? "Turning Bluetooth off disconnects this phone. The device keeps its pairings, but you will need another way to reach it to turn Bluetooth back on."
                        : "Turning Bluetooth off prevents direct Bluetooth connections. The device keeps its pairings."
                )
            }

            Section {
                if model.supportsBluetoothPairing {
                    if let count = reading?.properties.bleBondCount {
                        RemoteValueRow("Paired phones", value: "\(count)")
                    } else {
                        RemoteNotRead(title: "Paired phones")
                    }
                }
                RemoteValueRow("Currently Connected", value: connectionSummary)
            } header: {
                Text("Status")
            } footer: {
                RemoteReadingFooter(reading: reading, isBusy: model.isBusy)
            }

            if model.supportsBluetoothPairing {
                Section {
                    if let draft = Binding($draft) {
                        RemoteToggleField(
                            "Pairing mode",
                            field: draft.pairing,
                            problem: problems[draft.wrappedValue.pairing.propertyId]
                        )
                    } else {
                        RemoteReadOnlyToggle("Pairing mode", isOn: nil)
                    }
                    Button("Clear Pairings…", role: .destructive) { isConfirmingClear = true }
                } footer: {
                    Text(
                        "Pairing mode lets another phone pair without pressing anything on the device. It closes by itself after a short while, or when a phone pairs. Clearing forgets every paired phone and the pairing PIN."
                    )
                }
            }

        }
        .confirmationDialog(
            "Clear Every Pairing?",
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
            apply: { await model.applyAndRebuild($draft) },
            review: review,
            applyWarning: applyWarning(review?.warning)
        )
        .draft($draft, from: model, revision: reading?.revision)
    }

    /// Whether anyone is on the device's Bluetooth right now.
    ///
    /// Over the mesh this is the interesting row on the screen—it is the
    /// only way to ask whether someone else is on the device. Over
    /// Bluetooth it can only ever say yes, because the phone reading it is
    /// the connection.
    private var connectionSummary: String {
        guard let state = reading?.properties.bleLink else { return "Not read" }
        return state == 0 ? "No" : "Yes"
    }

    /// The one confirmation Apply gets. Stranding the device outranks the
    /// pairing window: a change that does both is confirmed for the harm
    /// it can do, not the door it opens.
    private func applyWarning(_ warning: MobileApplyWarning?) -> (title: String, message: String)? {
        switch warning {
        case .disablesBluetooth:
            disableWarning
        case .opensPairing:
            (
                title: String(
                    localized: "Turn On Pairing Mode",
                    comment: "Confirmation title and button: open a managed device's Bluetooth pairing window."
                ),
                message: String(
                    localized: """
                        While pairing mode is on, any phone nearby can pair with \
                        this device. A phone that pairs can manage it and read \
                        everything it holds.
                        """,
                    comment: "Confirmation message before opening a managed device's Bluetooth pairing window."
                )
            )
        case .strandsRadio, .disablesWifi, .changesStaticAddressing, nil:
            nil
        }
    }

    /// What clearing costs, which is not the same question on every link.
    private var clearWarning: String {
        let paired = reading?.properties.bleBondCount.map(Int.init) ?? 0
        return switch (overThisLink, paired) {
        case (true, 0):
            String(
                localized: "Every phone paired with this device, including this one, will be forgotten. The device then opens a pairing window so you can pair again.",
                comment: "Clear Pairings confirmation, over the device's own Bluetooth, when the count of paired phones is unknown."
            )
        case (true, let count):
            String(
                localized: "All \(count) phones paired with this device, including this one, will be forgotten. The device then opens a pairing window so you can pair again.",
                comment: "Clear Pairings confirmation, over the device's own Bluetooth: the count of paired phones. Has plural variants."
            )
        case (false, 0):
            String(
                localized: "Every phone paired with this device will be forgotten. The device then opens a pairing window so someone can pair again.",
                comment: "Clear Pairings confirmation, device reached some other way than its own Bluetooth, when the count of paired phones is unknown."
            )
        case (false, let count):
            String(
                localized: "All \(count) phones paired with this device will be forgotten. The device then opens a pairing window so someone can pair again.",
                comment: "Clear Pairings confirmation, device reached some other way than its own Bluetooth: the count of paired phones. Has plural variants."
            )
        }
    }

    /// The stranding warning, in the terms of the link it would strand.
    /// The core asks for it only when the device is reached over its own
    /// Bluetooth: the companion radio, or a device being set up.
    ///
    /// Modeled on the Radio screen's: a change that can put a device out of
    /// reach is confirmed once, on every route into Apply.
    private var disableWarning: (title: String, message: String) {
        model.link == .administrative
            ? (
                title: String(
                    localized: "End This Session",
                    comment: "Confirmation title and button: turn off Bluetooth on a device being set up over it."
                ),
                message: String(
                    localized: """
                        Turning Bluetooth off disconnects the device and ends this \
                        setup session. The only way back is the controls on the \
                        device itself.
                        """,
                    comment: "Confirmation message before turning off Bluetooth on a device being set up over it."
                )
            )
            : (
                title: String(
                    localized: "Disconnect This Radio",
                    comment: "Confirmation title and button: turn off Bluetooth on the radio this phone is using."
                ),
                message: String(
                    localized: """
                        Turning Bluetooth off disconnects the radio this phone is \
                        using, and the mesh goes with it. The only way back is the \
                        controls on the device itself.
                        """,
                    comment: "Confirmation message before turning off Bluetooth on the radio this phone is using."
                )
            )
    }
}
