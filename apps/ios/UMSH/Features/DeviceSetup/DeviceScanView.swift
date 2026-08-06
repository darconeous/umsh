import SwiftUI

/// The live list of nearby UMSH devices, driven by the administrative
/// session's own scan.
///
/// This is not `RadioPickerView`: that one picks *this phone's* radio and
/// its selection is a persistent binding. Here a selection is a foreground
/// visit, and the phone's own radio is the one entry the list steers away
/// from — administering the device the companion connection is already
/// holding would put two links in contention for one peripheral.
struct DeviceScanView: View {
    let controller: AdminFlowController

    @State private var hasSearchedAwhile = false

    var body: some View {
        List {
            Section {
                if controller.devices.isEmpty {
                    HStack(spacing: 12) {
                        ProgressView()
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Searching for devices")
                            Text(hasSearchedAwhile
                                 ? "Make sure the device is powered on and nearby."
                                 : "Nearby UMSH devices will appear here.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                } else {
                    ForEach(controller.devices) { device in
                        Button {
                            Task { await controller.select(device) }
                        } label: {
                            DeviceScanRow(
                                device: device,
                                isCompanion: controller.isCompanion(device),
                                isBusy: controller.busyDevice == device.id
                            )
                        }
                        .disabled(controller.isBusy || controller.isCompanion(device))
                    }
                }
            } header: {
                Text("Nearby devices")
            } footer: {
                footer
            }
        }
        .navigationTitle("Choose a Device")
        .onAppear { controller.startDiscovery() }
        .onDisappear {
            // Connecting already stopped the scan; this covers backing out.
            Task { await controller.stopDiscovery() }
        }
        .task {
            // A gentle nudge after a few quiet seconds, without failing the
            // scan — the device may simply be booting.
            try? await Task.sleep(nanoseconds: 4 * 1_000_000_000)
            hasSearchedAwhile = true
        }
    }

    @ViewBuilder
    private var footer: some View {
        if let problem = controller.problem {
            Text(problem).foregroundStyle(.red)
        } else if controller.devices.contains(where: controller.isCompanion) {
            Text("This phone's own radio is listed but cannot be set up from here — use the companion radio screen for that. Devices drop out of the list a few seconds after they stop advertising.")
        } else {
            Text("Discovery keeps running while this list is open. Devices drop out a few seconds after they stop advertising.")
        }
    }
}

private struct DeviceScanRow: View {
    let device: DiscoveredRadio
    let isCompanion: Bool
    let isBusy: Bool

    var body: some View {
        HStack(spacing: 12) {
            SignalStrengthIcon(bars: device.signalBars, hasSignal: device.hasSignal)
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(device.name ?? "Unnamed device")
                        .foregroundStyle(.primary)
                    if isCompanion {
                        Text("This phone's radio")
                            .font(.caption2.weight(.semibold))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 1)
                            .background(.tint.opacity(0.15), in: Capsule())
                            .foregroundStyle(.tint)
                    }
                }
                Text(device.hasSignal ? "\(device.rssiDBm) dBm" : "Signal unavailable")
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if isBusy {
                ProgressView()
            }
        }
        .contentShape(Rectangle())
    }
}
