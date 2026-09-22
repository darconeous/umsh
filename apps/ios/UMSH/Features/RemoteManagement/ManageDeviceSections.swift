import SwiftUI

struct ManageDeviceIdentitySection: View {
    let model: ManageDeviceModel

    var body: some View {
        Section {
            if let card = model.card {
                LabeledContent("Name", value: card.deviceName ?? model.fallbackName)
                if let model = card.deviceModel {
                    LabeledContent("Model", value: model)
                }
                LabeledContent("Firmware", value: card.deviceVersion ?? "Not reported")
                if card.supportsAlert {
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
                Text("Asked \(asOf.formatted(.relative(presentation: .named))).")
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

    var body: some View {
        if model.supportsRestart || model.offersFactoryReset {
            Section {
                if model.supportsRestart {
                    Button("Restart This Device…", role: .destructive) {
                        confirmsRestart = true
                    }
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
