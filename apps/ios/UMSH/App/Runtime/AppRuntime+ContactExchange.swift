import Foundation
import OSLog
import UMSHMobileCore

extension AppRuntime {
    // MARK: - Contact exchange

    /// Add Peer's contact exchange, for the views.
    var contactExchange: ContactExchange {
        ContactExchange(
            state: meet,
            ownModel: AppCoreHost.platformModel,
            radioReady: radioSnapshot.carriesThisPhone,
            exchangedPeer: exchangedPeer,
            setWanted: setMeetWanted,
            ask: askToExchange(device:),
            answer: answerExchange(accept:),
            confirm: confirmCode(same:),
            backOut: backOutOfExchange,
            openAgain: openMeetAgain
        )
    }

    /// Add Peer appeared or went, or the app came to or left the
    /// foreground with it showing. The core opens the exchange whenever the
    /// radio can carry it and closes it otherwise.
    func setMeetWanted(_ wanted: Bool) async {
        guard wanted != meetWanted else { return }
        meetWanted = wanted
        if !wanted {
            exchangedPeer = nil
        }
        do {
            try await core?.setMeetWanted(wanted: wanted)
        } catch {
            Self.logger.debug("Meet not settled: \(String(describing: error), privacy: .public)")
        }
    }

    func askToExchange(device: UInt32) async {
        _ = try? await core?.askToExchange(device: device)
    }

    /// Answers the device that asked; on Not now the core opens again under
    /// a new key. Views can call this after the question has gone (a card
    /// dismissing once the answer has moved the exchange on), so it checks
    /// that a device is still asking.
    func answerExchange(accept: Bool) async {
        guard meet?.exchange.askedBy != nil else { return }
        try? await core?.answerExchange(accept: accept)
    }

    func confirmCode(same: Bool) async {
        try? await core?.confirmCode(same: same)
    }

    /// Ends the attempt under way; the core opens a fresh one. Like
    /// answering, it checks the live state: the screen it backs out of can
    /// be leaving because the attempt is already over.
    func backOutOfExchange() async {
        guard meet?.exchange.isUnderWay == true else { return }
        try? await core?.backOutOfExchange()
    }

    /// Try again, after an attempt ended: the core counts an ended attempt
    /// as one to back out of, and backing out opens a fresh one.
    func openMeetAgain() async {
        exchangedPeer = nil
        try? await core?.backOutOfExchange()
    }
}
