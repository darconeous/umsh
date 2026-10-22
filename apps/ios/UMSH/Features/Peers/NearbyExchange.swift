import SwiftUI
import UMSHMobileCore

/// Add Peer's contact exchange (`app-meet.md`) as the views see it: where
/// it stands, and what they can do about it.
///
/// Deliberately not `Sendable`, like `PeerActions`: main-actor operations
/// owned by the app root, handed to views that also live on the main actor.
struct ContactExchange {
    var state: MobileMeetStateRecord?
    /// This phone's platform id, which its Hellos carry.
    var ownModel: UInt16
    /// The radio can carry this phone's traffic.
    var radioReady: Bool
    /// The peer the last exchange produced, recorded unsaved.
    var exchangedPeer: PeerSummary?
    /// Add Peer is showing with the app in the foreground, or no longer.
    var setWanted: (Bool) async -> Void
    var ask: (UInt32) async -> Void
    /// Exchange (`true`) or Not now, while a device is asking; nothing
    /// otherwise.
    var answer: (Bool) async -> Void
    /// Same (`true`) or Different.
    var confirm: (Bool) async -> Void
    /// Ends the attempt under way and opens a fresh one; nothing when none
    /// is.
    var backOut: () async -> Void
    /// A fresh attempt under a new key: Try again, and Done.
    var openAgain: () async -> Void
}

/// Add Peer: Nearby above entering an address, run as one exchange for as
/// long as the sheet shows. Once contacts cross, the sheet becomes the new
/// peer's page, unsaved.
struct AddPeerSheet<PeerPage: View>: View {
    let exchange: ContactExchange
    let inspectPeerIdentity: (String) async -> Result<MeshNodeURIPreview, MeshEngineError>
    let save: (MeshNodeURIPreview, PeerImportDetails, Bool) async -> Void
    @ViewBuilder let peerPage: (PeerSummary) -> PeerPage

    @Environment(\.scenePhase) private var scenePhase
    @State private var handedOff: PeerSummary?

    var body: some View {
        NavigationStack {
            if let handedOff {
                peerPage(handedOff)
            } else {
                NodeImportView(
                    inspectPeerIdentity: inspectPeerIdentity,
                    save: save,
                    exchange: exchange
                )
            }
        }
        .onAppear { settle() }
        .onDisappear { Task { await exchange.setWanted(false) } }
        .onChange(of: scenePhase) { settle() }
        .onChange(of: exchange.exchangedPeer?.identity.canonicalAddress) {
            if let peer = exchange.exchangedPeer, handedOff == nil {
                handedOff = peer
                settle()
            }
        }
    }

    private func settle() {
        let wanted = scenePhase == .active && handedOff == nil
        Task { await exchange.setWanted(wanted) }
    }
}

/// Nearby: the devices that have Add Peer open too, each by its model and
/// its color for this visit, and this phone's own color beside You.
struct NearbySection: View {
    let exchange: ContactExchange

    var body: some View {
        Section {
            if !exchange.radioReady {
                Text("Connect a companion radio set up for this phone to exchange contacts.")
                    .foregroundStyle(.secondary)
            } else if let devices = exchange.state?.devices, !devices.isEmpty {
                ForEach(devices, id: \.id) { device in
                    Button {
                        Task { await exchange.ask(device.id) }
                    } label: {
                        NearbyRow(device: device)
                    }
                    .foregroundStyle(.primary)
                }
            } else {
                HStack(spacing: 12) {
                    Image(systemName: "dot.radiowaves.left.and.right")
                        .symbolEffect(.variableColor.iterative)
                        .foregroundStyle(.secondary)
                    Text("Nothing nearby yet.")
                        .foregroundStyle(.secondary)
                }
            }
        } header: {
            HStack {
                Text("Nearby")
                Spacer()
                if let own = exchange.state?.ownColorRgb {
                    HStack(spacing: 6) {
                        Text("You")
                        MeetGlyph(color: own, model: exchange.ownModel, diameter: 22)
                    }
                }
            }
        }
    }
}

private struct NearbyRow: View {
    let device: MobileMeetDeviceRecord

    var body: some View {
        HStack(spacing: 12) {
            MeetGlyph(color: device.colorRgb, model: device.model)
            Text(MeetModels.bundled.name(model: device.model))
                .font(.body.weight(.semibold))
            Spacer()
            if let nearness = device.nearness {
                MeetNearness(nearness: nearness)
            }
        }
        .padding(.vertical, 2)
    }
}

/// The card a device asking to exchange opens: its model and color, and
/// the answers. Swiping it away answers as Not now does.
struct ExchangeAskedCard: View {
    let device: MobileMeetDeviceRecord
    let answer: (Bool) async -> Void

    var body: some View {
        VStack(spacing: 16) {
            HStack(spacing: 12) {
                MeetGlyph(color: device.colorRgb, model: device.model)
                VStack(alignment: .leading) {
                    Text(MeetModels.bundled.name(model: device.model))
                        .font(.headline)
                    Text("Exchange contacts?")
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            PairedButtons(
                secondary: "Not now", { reply(false) },
                primary: "Exchange", { reply(true) }
            )
        }
        .padding(20)
        .presentationDetents([.height(180)])
    }

    /// The card goes when the answer moves the exchange on; dismissing it
    /// here would read as swiping it away.
    private func reply(_ accept: Bool) {
        Task { await answer(accept) }
    }
}

/// A device that asked to exchange, as a sheet presents it.
struct AskingDevice: Identifiable {
    let device: MobileMeetDeviceRecord
    var id: UInt32 { device.id }
}

extension MobileMeetExchange {
    /// The device that asked, while it waits for this phone's holder.
    var askedBy: MobileMeetDeviceRecord? {
        if case let .asked(device) = self { device } else { nil }
    }

    /// The exchange has gone past Nearby: this phone asked or agreed, the
    /// codes are up, or it ended there.
    var isUnderWay: Bool {
        switch self {
        case .asking, .accepted, .comparing, .ended: true
        case .closed, .opening, .idle, .asked, .exchanged: false
        }
    }
}
