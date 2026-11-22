import SwiftUI

struct ManageDeviceIdentitySection: View {
    let model: ManageDeviceModel

    var body: some View {
        Section {
            if let card = model.card {
                RemoteValueRow("Name", value: card.deviceName ?? model.fallbackName)
                if let model = card.deviceModel {
                    RemoteValueRow("Model", value: model)
                }
                RemoteValueRow("Firmware", value: card.deviceVersion ?? "Not reported")
                if card.supportsAlert && !model.enteredDfu {
                    findButton
                }
            } else if model.isBusy {
                ProgressView("Asking the device what it is")
                    .frame(maxWidth: .infinity)
            } else {
                // Reached when the first card fetch failed. The problem
                // section below says why, and the toolbar's refresh is how
                // to try again.
                Text("This device has not said what it is yet.")
                    .foregroundStyle(.secondary)
            }
        } footer: {
            if let asOf = model.cardAsOf {
                AgeLabel(since: asOf) { age in
                    Text("Asked \(age).", comment: "When the device was last asked what it is. The placeholder is an age, such as 5 min. ago or just now.")
                }
            }
        }
    }

    private var findButton: some View {
        Button {
            Task { await model.setAlert(model.alert == .locating ? .none : .locating) }
        } label: {
            Label(
                model.alert == .locating ? "Stop Locating" : "Find This Device",
                systemImage: model.alert == .locating ? "bell.slash" : "bell"
            )
        }
    }
}

struct ManageDeviceCategoriesSection: View {
    let model: ManageDeviceModel
    let browsing: RemotePeerBrowsing

    var body: some View {
        Section {
            ForEach(ManageDeviceCategory.offered(by: model)) { entry in
                NavigationLink {
                    entry.destination(model, browsing)
                } label: {
                    Label(entry.title, systemImage: entry.symbol)
                }
            }
        }
    }
}

struct ManageDeviceLifecycleSection: View {
    let model: ManageDeviceModel
    @Binding var confirmsRestart: Bool
    @Binding var confirmsFactoryReset: Bool
    @Binding var confirmsDfu: Bool

    var body: some View {
        // DFU and a factory reset both end in a restart, so a device that
        // cannot restart is offered none of the three.
        if model.supportsRestart {
            Section {
                Button("Enter DFU Mode…", role: .destructive) {
                    confirmsDfu = true
                }
                Button("Restart This Device…", role: .destructive) {
                    confirmsRestart = true
                }
                if model.offersFactoryReset {
                    Button("Factory Reset…", role: .destructive) {
                        confirmsFactoryReset = true
                    }
                }
            } footer: {
                Text(model.offersFactoryReset
                     ? "A restart keeps everything the device has saved. A factory reset keeps nothing, the device's own identity included."
                     : "A restart keeps everything the device has saved. Erasing a device is only offered while it is connected to this phone.")
            }
        }
    }
}
