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

        var recovery = RadioActivationRecovery()
        precondition(recovery.nextDelay() == 1)
        precondition(recovery.nextDelay() == 2)
        precondition(recovery.nextDelay() == 4)
        precondition(recovery.nextDelay() == nil)
        recovery.reset() // foreground visit or manual Reconnect
        precondition(recovery.nextDelay() == 1)
        print("BLE lifecycle, stale-callback tickets, and accessory recovery checks passed")
    }
}
