import Foundation
import CoreBluetooth

@main
struct RadioRecoverySmokeTest {
    static func main() {
        precondition(BluetoothErrorText.invalidatesTransport(NSError(domain: CBErrorDomain, code: CBError.notConnected.rawValue)))
        precondition(BluetoothErrorText.invalidatesTransport(NSError(domain: CBErrorDomain, code: CBError.peripheralDisconnected.rawValue)))
        precondition(BluetoothErrorText.invalidatesTransport(NSError(domain: CBATTErrorDomain, code: CBATTError.invalidHandle.rawValue)))
        precondition(!BluetoothErrorText.invalidatesTransport(NSError(domain: CBATTErrorDomain, code: CBATTError.writeNotPermitted.rawValue)))
        var link = RadioLinkLifecycle()
        func attach(_ link: inout RadioLinkLifecycle) {
            link.begin()
            precondition(link.advance(from: .connecting, to: .services))
            precondition(link.advance(from: .services, to: .characteristics))
            precondition(link.advance(from: .characteristics, to: .subscribing))
            precondition(link.advance(from: .subscribing, to: .ready))
        }
        // A radio away for hours keeps its pending connection; attachment
        // watchdogs start only once Bluetooth has established the link.
        link.begin()
        precondition(link.deadlineSeconds == nil && !link.acceptsGatt)
        precondition(link.advance(from: .connecting, to: .services))
        let lostServicesCallback = link.ticket
        precondition(link.deadlineSeconds == 10)
        link.retire() // discovery deadline expired
        precondition(link.ticket != lostServicesCallback && !link.acceptsGatt)
        precondition(!link.advance(from: .services, to: .characteristics))
        let lostDisconnectCallback = link.ticket
        precondition(link.deadlineSeconds == 5)
        link.clear() // cancellation deadline replaces the manager
        precondition(link.phase == .idle && link.ticket != lostDisconnectCallback)

        attach(&link)
        let oldAttachment = link.ticket
        precondition(link.acceptsGatt)
        link.retire() // user disconnect, before any CB callback
        precondition(!link.acceptsGatt)
        precondition(!link.advance(from: .subscribing, to: .ready))
        attach(&link)
        precondition(link.ticket != oldAttachment, "A reused peripheral cannot revive an old attachment")
        precondition(!link.advance(from: .subscribing, to: .ready), "Duplicate subscription callbacks cannot restart ULCP")

        // Manager reset, Service Changed, and transport failure all retire
        // the old epoch before reusing a radio or starting new GATT work.
        for _ in 0..<3 {
            let old = link.ticket
            link.clear()
            precondition(!link.acceptsGatt)
            attach(&link)
            precondition(link.ticket.generation != old.generation)
        }
        link.begin()
        precondition(link.advance(from: .connecting, to: .services))
        precondition(link.advance(from: .services, to: .characteristics))
        precondition(link.deadlineSeconds == 10)
        precondition(link.advance(from: .characteristics, to: .subscribing))
        precondition(link.deadlineSeconds == 60)

        var control = RadioControlDeadlines()
        control.update(pending: [1, 2], now: 100)
        precondition(control.next == 108)
        // Incoming battery notifications don't answer the missing request.
        for now in [101.0, 104, 107] {
            control.update(pending: [1, 2], now: now)
            precondition(control.next == 108)
        }
        // A response can start more work without extending another request.
        control.update(pending: [2, 3], now: 107)
        precondition(control.next == 108)
        control.update(pending: [3], now: 107.5)
        precondition(control.next == 115)
        control.update(pending: [], now: 108) // only raw PHY TX remains
        precondition(control.next == nil)
        control.update(pending: [4], now: 109) // control + slow PHY TX
        precondition(control.next == 117)
        control.reset() // timeout retires the session, not only Swift callers
        control.update(pending: [1], now: 120)
        precondition(control.next == 128)
        control.update(pending: [1], completed: 1, now: 127)
        precondition(control.next == 135, "Immediate transaction ID reuse gets a fresh deadline")

        var recovery = RadioActivationRecovery()
        precondition(recovery.nextDelay() == 1)
        precondition(recovery.nextDelay() == 2)
        precondition(recovery.nextDelay() == 4)
        precondition(recovery.nextDelay() == nil)
        recovery.reset() // foreground visit or manual Reconnect
        precondition(recovery.nextDelay() == 1)
        print("BLE lifecycle, stale-callback tickets, control deadlines, and accessory recovery checks passed")
    }
}
