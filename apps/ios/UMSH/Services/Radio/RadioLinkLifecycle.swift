import Foundation

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
