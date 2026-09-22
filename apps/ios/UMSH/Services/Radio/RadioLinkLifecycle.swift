import Foundation

/// A caller can stop waiting without freeing the radio's in-flight operation
/// slot. The session retains this ticket until its answer or teardown, so a
/// late answer cannot complete a newer request. The lock arbitrates only
/// continuation ownership; protocol state remains on the session queue.
final class RadioOperationWaiter<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, any Error>?
    private var cancelled = false

    var isCancelled: Bool { lock.withLock { cancelled } }

    func install(_ continuation: CheckedContinuation<Value, any Error>) -> Bool {
        let accepted = lock.withLock {
            guard !cancelled else { return false }
            self.continuation = continuation
            return true
        }
        if !accepted { continuation.resume(throwing: CancellationError()) }
        return accepted
    }

    func cancel() {
        let waiter = lock.withLock {
            cancelled = true
            let waiter = continuation
            continuation = nil
            return waiter
        }
        waiter?.resume(throwing: CancellationError())
    }

    func resume(returning value: Value) { finish(.success(value)) }
    func resume(throwing error: any Error) { finish(.failure(error)) }
    func resume() where Value == Void { finish(.success(())) }

    private func finish(_ result: Result<Value, any Error>) {
        let waiter = lock.withLock {
            let waiter = continuation
            continuation = nil
            return waiter
        }
        waiter?.resume(with: result)
    }
}

/// Admission and deadline tickets for one BLE attachment. User intent lives
/// separately: retiring an attachment must not erase the saved radio.
struct RadioLinkLifecycle {
    enum Phase: Equatable {
        case idle, connecting, services, characteristics, subscribing, ready, disconnecting
    }
    struct Ticket: Equatable {
        let generation: UInt64
        let phase: Phase
    }
    private(set) var generation: UInt64 = 0
    private(set) var phase: Phase = .idle
    var ticket: Ticket { Ticket(generation: generation, phase: phase) }
    var deadlineSeconds: TimeInterval? {
        switch phase {
        case .services, .characteristics: 10
        case .subscribing: 60 // The system may be waiting for passkey entry.
        case .disconnecting: 5
        case .idle, .connecting, .ready: nil
        }
    }
    var acceptsGatt: Bool {
        switch phase {
        case .services, .characteristics, .subscribing, .ready: true
        default: false
        }
    }
    mutating func begin() {
        generation &+= 1
        phase = .connecting
    }
    @discardableResult
    mutating func advance(from expected: Phase, to next: Phase) -> Bool {
        guard phase == expected else { return false }
        phase = next
        return true
    }
    mutating func retire() {
        generation &+= 1
        phase = .disconnecting
    }
    mutating func clear() {
        generation &+= 1
        phase = .idle
    }
}

/// Retry a broken accessory session a few times, then wait for a foreground
/// visit or explicit user action instead of polling forever.
struct RadioActivationRecovery {
    private var attempts = 0
    mutating func nextDelay() -> Int? {
        guard attempts < 3 else { return nil }
        let delay = 1 << attempts
        attempts += 1
        return delay
    }
    mutating func reset() { attempts = 0 }
}

/// Each control transaction keeps its original deadline until Rust retires it.
/// Unsolicited traffic and raw LoRa transmissions cannot extend that deadline.
struct RadioControlDeadlines {
    private var deadlines: [UInt8: TimeInterval] = [:]
    var next: TimeInterval? { deadlines.values.min() }
    mutating func update(pending: [UInt8], completed: UInt8? = nil, now: TimeInterval) {
        if let completed { deadlines.removeValue(forKey: completed) }
        let pending = Set(pending)
        deadlines = deadlines.filter { pending.contains($0.key) }
        for id in pending where deadlines[id] == nil { deadlines[id] = now + 8 }
    }
    mutating func reset() { deadlines.removeAll() }
}
