import Foundation
import UMSHMobileCore

// RadioConnection's peer-event convenience method refers to the app's UI
// model. This test never resolves peers; only its identity shape is needed.
struct PeerSummary {
    let identity: MeshPublicIdentity
}

struct ChannelRegistration {
    let record: MobileChannelRegistrationRecord
}

private final class TestLink: UlcpFrameLink {
    var linkIsReady = true
    let linkID: UUID? = UUID()
    let linkName: String? = "Test radio"
    var linkIsBoundRadio: Bool { true }
    var linkCanReconnect: Bool { true }
    var invalidations: [Bool] = []
    var writes: [Data] = []
    var dfuEntries = 0
    var onDfu: (() -> Void)?
    func linkSend(frame: Data, rawTransactionID: UInt8?) { writes.append(frame) }
    func linkResetFraming() { writes.removeAll() }
    func linkInvalidate(retrying: Bool) { invalidations.append(retrying); linkIsReady = false }
    func linkDidAttach() {}
    func linkDidReportName(_ name: String) {}
    func linkAbandonBinding() {}
    func linkDidEnterDfu() { dfuEntries += 1; onDfu?() }
}

@main
struct RadioSessionRecoverySmokeTest {
    static func main() async throws {
        try recoveryTests()
        try await dfuTests()
    }

    static func dfuTests() async throws {
        for dfu in [false, true] {
            for status: UInt32 in [0, 2, 5, 1] {
                let queue = DispatchQueue(label: "dfu-confirmation-test")
                let session = UlcpRadioSession(sessionQueue: queue)
                let link = TestLink()
                let (events, started) = AsyncStream<Void>.makeStream()
                queue.sync {
                    session.adopt(link: link)
                    session.snapshot.linkState = .attached
                    link.onDfu = { session.sessionDidLoseLink(); link.linkIsReady = false }
                }
                let operation = Task {
                    try await session.performLocalManagement(dfu: dfu) { core in
                        started.yield(())
                        started.finish()
                        return try core.begin(selectedHostKey: nil)
                    }
                }
                for await _ in events { break }
                try queue.sync {
                    precondition(link.dfuEntries == 0, "sending must not confirm entry")
                    var update = session.ulcpSession.abandonRawTransmits(transactionIds: Data())
                    update.managementEvent = UlcpLocalManagementEventRecord(answers: [], statusCode: status)
                    try session.applySessionUpdate(update)
                }
                let response = try await operation.value
                precondition(response.statusCode == status, "immediate disconnect must not lose the successful response")
                queue.sync {
                    precondition(link.dfuEntries == (dfu && status == 0 ? 1 : 0))
                    if dfu && status == 0 {
                        precondition(session.localManagementWaiter == nil)
                        precondition(!link.linkIsReady)
                    }
                    session.sessionDidLoseLink()
                }
            }
        }
        try await DfuEntryError.perform { 0 }
        for status: UInt32? in [2, 5, 1, nil] {
            do {
                try await DfuEntryError.perform { status }
                preconditionFailure("Only STATUS_OK confirms DFU")
            } catch let error as DfuEntryError {
                switch (status, error) {
                case (2, .unsupported), (5, .unsupported), (1, .refused(1)), (nil, .unconfirmed): break
                default: preconditionFailure("Incorrect DFU failure classification")
                }
            }
        }
        do {
            try await DfuEntryError.perform { throw RadioConnectionError.radioNotFound }
            preconditionFailure("A disconnect cannot confirm DFU")
        } catch DfuEntryError.unconfirmed {}
        print("DFU response confirmation, immediate disconnect, remote-style retention, and refusal checks passed")
    }

    static func recoveryTests() throws {
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
