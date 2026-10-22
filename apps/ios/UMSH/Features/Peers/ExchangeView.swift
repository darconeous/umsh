import SwiftUI
import UMSHMobileCore

/// A contact exchange with a device from Nearby: waiting for it, the code
/// both holders compare with Same and Different, and how it ended. Back
/// backs out.
struct ExchangeView: View {
    let exchange: ContactExchange
    /// Leaves Add Peer altogether.
    let leave: () -> Void

    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            content
            Spacer()
        }
        .padding()
        .frame(maxWidth: .infinity)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .principal) {
                if let device = exchange.state?.device {
                    HStack(spacing: 8) {
                        MeetGlyph(color: device.colorRgb, model: device.model, diameter: 26)
                        Text(name(of: device)).font(.headline)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var content: some View {
        switch exchange.state?.exchange {
        case let .comparing(device, code, sent):
            Text(Self.digits(code))
                .font(.system(size: 56, weight: .semibold, design: .monospaced))
                .monospacedDigit()
                .accessibilityLabel(Text(Self.digits(code)))
            Text("Same code on the other screen?")
                .foregroundStyle(.secondary)
            if sent {
                Label("Same", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .font(.headline)
                waiting(for: device)
            } else {
                PairedButtons(
                    secondary: "Different", { Task { await exchange.confirm(false) } },
                    primary: "Same", { Task { await exchange.confirm(true) } }
                )
            }
        case let .ended(reason):
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 44))
                .foregroundStyle(.red)
            Text(reason == .different ? "Codes differ. Nothing saved." : "Not exchanged. Nothing saved.")
                .font(.headline)
                .multilineTextAlignment(.center)
            PairedButtons(
                secondary: "Done", leave,
                primary: "Try again", { Task { await exchange.openAgain() } }
            )
        case let .asking(device), let .accepted(device):
            waiting(for: device)
        default:
            ProgressView()
        }
    }

    private func waiting(for device: MobileMeetDeviceRecord) -> some View {
        HStack(spacing: 10) {
            Text("Waiting for \(name(of: device))")
                .foregroundStyle(.secondary)
            ProgressView()
        }
    }

    private func name(of device: MobileMeetDeviceRecord) -> String {
        MeetModels.bundled.name(model: device.model)
    }

    /// A code as its holder reads it aloud: two groups of three.
    static func digits(_ code: UInt32) -> String {
        let padded = String(format: "%06u", code)
        return "\(padded.prefix(3)) \(padded.suffix(3))"
    }
}

/// Two answers side by side, each filling its half, the one that moves the
/// exchange on last.
struct PairedButtons: View {
    let secondary: LocalizedStringKey
    let secondaryAction: () -> Void
    let primary: LocalizedStringKey
    let primaryAction: () -> Void

    init(
        secondary: LocalizedStringKey, _ secondaryAction: @escaping () -> Void,
        primary: LocalizedStringKey, _ primaryAction: @escaping () -> Void
    ) {
        self.secondary = secondary
        self.secondaryAction = secondaryAction
        self.primary = primary
        self.primaryAction = primaryAction
    }

    var body: some View {
        HStack(spacing: 12) {
            Button(action: secondaryAction) {
                Text(secondary).frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            Button(action: primaryAction) {
                Text(primary).frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
        }
        .controlSize(.large)
    }
}
