import Foundation
import UMSHMobileCore

// RadioConnection's peer-event convenience method refers to the app's UI
// model. This test never resolves peers; only its identity shape is needed.
struct PeerSummary {
    let identity: MeshPublicIdentity
}

private final class TestLink: UlcpFrameLink {
    var linkIsReady = true
    let linkID: UUID? = UUID()
    let linkName: String? = "Test radio"
    var linkIsBoundRadio: Bool { true }
    var linkCanReconnect: Bool { true }
    var invalidations: [Bool] = []
    var writes: [Data] = []
    func linkSend(frame: Data, rawTransactionID: UInt8?) { writes.append(frame) }
    func linkResetFraming() { writes.removeAll() }
    func linkInvalidate(retrying: Bool) { invalidations.append(retrying); linkIsReady = false }
    func linkDidAttach() {}
    func linkDidReportName(_ name: String) {}
    func linkAbandonBinding() {}
}

@main
struct RadioSessionRecoverySmokeTest {
    static func main() throws {
        let queue = DispatchQueue(label: "radio-recovery-test")
        let session = UlcpRadioSession(sessionQueue: queue)
        let link = TestLink()
        queue.sync {
            session.adopt(link: link)
            session.linkDidBecomeReady()
            precondition(!link.writes.isEmpty)
        }
        // A busy radio can produce updates while one control answer never
        // arrives. Exercise the real session and its Dispatch deadline, not
        // just the deadline helper, without a CoreBluetooth peripheral.
        for _ in 0..<9 {
            Thread.sleep(forTimeInterval: 1)
            try queue.sync {
                if link.linkIsReady {
                    let update = session.ulcpSession.abandonRawTransmits(transactionIds: Data())
                    try session.applySessionUpdate(update)
                }
            }
        }
        queue.sync {
            precondition(link.invalidations == [true], "A silent control request must trigger recovery despite other updates")
            precondition(session.snapshot.linkState == .reconnecting)
            let update = session.ulcpSession.abandonRawTransmits(transactionIds: Data())
            precondition(update.pendingControlTransactions.isEmpty, "Timed-out requests must be retired in Rust")
        }
        // A new attachment can start immediately after the failed one, and
        // teardown rejects any delayed update trying to resurrect its state.
        try queue.sync {
            link.linkIsReady = true
            session.linkDidBecomeReady()
            precondition(!link.writes.isEmpty)
            let stale = session.ulcpSession.abandonRawTransmits(transactionIds: Data())
            session.sessionDidLoseLink()
            link.linkIsReady = false
            do {
                try session.applySessionUpdate(stale)
                preconditionFailure("A retired link must reject a late update")
            } catch RadioConnectionError.radioNotFound {}
        }
        Thread.sleep(forTimeInterval: 9)
        queue.sync {
            precondition(link.invalidations.count == 1, "An old timer cannot act after teardown")
        }
        print("Actual ULCP session timeout recovery, Rust retirement, and stale-update checks passed")
    }
}
