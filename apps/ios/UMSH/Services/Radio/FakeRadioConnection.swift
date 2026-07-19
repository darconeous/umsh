import Foundation

actor FakeRadioConnection: RadioConnection {
    private var snapshot: RadioSnapshot
    private var continuations: [UUID: AsyncStream<RadioSnapshot>.Continuation] = [:]
    private var frameContinuations: [UUID: AsyncStream<RadioReceivedFrame>.Continuation] = [:]

    init(snapshot: RadioSnapshot = .previewReady) {
        self.snapshot = snapshot
    }

    func snapshots() -> AsyncStream<RadioSnapshot> {
        let initial = snapshot
        return AsyncStream { continuation in
            let id = UUID()
            continuations[id] = continuation
            continuation.yield(initial)
            continuation.onTermination = { [weak self] _ in
                Task { await self?.removeContinuation(id) }
            }
        }
    }

    func receivedFrames() -> AsyncStream<RadioReceivedFrame> {
        AsyncStream { continuation in
            let id = UUID()
            frameContinuations[id] = continuation
            continuation.onTermination = { [weak self] _ in
                Task { await self?.removeFrameContinuation(id) }
            }
        }
    }

    func connect() async throws {
        publish(.previewReady)
    }

    func useHostIdentity(_ identity: MeshPublicIdentity?) async throws {}

    func autoConnect() async {}

    func claimForCurrentIdentity() async throws {
        publish(.previewReady)
    }

    func disconnect() async {
        publish(.disconnected)
    }

    func publish(_ newSnapshot: RadioSnapshot) {
        snapshot = newSnapshot
        for continuation in continuations.values {
            continuation.yield(newSnapshot)
        }
    }

    func publish(_ frame: RadioReceivedFrame) {
        for continuation in frameContinuations.values {
            continuation.yield(frame)
        }
    }

    private func removeContinuation(_ id: UUID) {
        continuations[id] = nil
    }

    private func removeFrameContinuation(_ id: UUID) {
        frameContinuations[id] = nil
    }
}
