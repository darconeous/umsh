@preconcurrency import CoreBluetooth
import Foundation

/// User-facing text for a CoreBluetooth failure.
///
/// `localizedDescription` on a CoreBluetooth error is written for whoever
/// is reading a crash log. A device that has never been paired answers with
/// **Encryption is insufficient** — the name of the ATT response, which
/// tells the person holding the radio nothing about what went wrong or what
/// to do about it.
///
/// Only failures a user can act on are translated here. Everything else
/// keeps the system text: an unhelpful accurate string beats an invented
/// one, and the raw error still reaches the log either way.
enum BluetoothErrorText {
    /// The device and this phone have no pairing, so the encrypted ULCP
    /// characteristics are unreadable.
    static let notPaired = """
        This device is not paired with this phone. Put it in pairing mode and \
        try again — most UMSH devices accept a new pairing only for a short \
        time after they are powered on.
        """

    /// The phone holds a pairing the device has since forgotten — a factory
    /// reset, or a bond table the device cleared. iOS will not re-pair until
    /// its stale record is removed, and only the user can remove it.
    static let pairingLost = """
        This device no longer recognizes its pairing with this phone. Forget \
        it in Settings › Bluetooth, then pair with it again.
        """

    /// The phone is addressing attributes that are no longer where it
    /// remembers them.
    ///
    /// iOS caches a bonded device's GATT database and reuses it across
    /// connections without re-reading it. A device whose firmware changed
    /// the shape of that database therefore receives requests aimed at
    /// whatever now occupies the old handles — a write lands on some
    /// unrelated attribute and is refused for its length, or the handle no
    /// longer exists at all. Nothing the app can do clears that cache.
    static let staleDatabase = """
        This phone is using an out-of-date copy of the device's Bluetooth \
        services, which happens after the device's firmware changes. Forget \
        the device in Settings › Bluetooth and pair with it again.
        """

    static func describe(_ error: any Error) -> String {
        let error = error as NSError
        switch error.domain {
        case CBATTErrorDomain:
            switch CBATTError.Code(rawValue: error.code) {
            case .insufficientEncryption, .insufficientAuthentication,
                 .insufficientAuthorization, .insufficientEncryptionKeySize:
                return notPaired
            case .invalidHandle, .attributeNotFound:
                // The device has no such attribute. Nothing but a cache
                // describing a database that no longer exists explains a
                // request being sent to a handle that is not there.
                return staleDatabase
            case .invalidAttributeValueLength:
                // Ambiguous on purpose. This is what a stale cache looks
                // like when the old handle now points at a smaller
                // attribute, but it is equally what a genuine oversize
                // write looks like, and claiming the first would send
                // someone to re-pair over a bug in this app.
                return """
                    The device refused a message for its size. If pairing with \
                    it again does not help, this is a fault in the app rather \
                    than something you can fix on the device.
                    """
            default:
                return error.localizedDescription
            }
        case CBErrorDomain:
            switch CBError.Code(rawValue: error.code) {
            case .peerRemovedPairingInformation:
                return pairingLost
            case .encryptionTimedOut:
                return """
                    Pairing with this device timed out. Many UMSH devices show \
                    a PIN only for a short window after powering on; restart \
                    the device and try again.
                    """
            case .tooManyLEPairedDevices:
                return """
                    This iPhone has paired with as many Bluetooth devices as it \
                    can hold. Forget one in Settings › Bluetooth, then try again.
                    """
            case .connectionTimeout:
                return "The device stopped responding."
            case .peripheralDisconnected:
                return "The device disconnected."
            default:
                return error.localizedDescription
            }
        default:
            return error.localizedDescription
        }
    }

    /// The failure as it should appear in a log: the plain-language text a
    /// user sees is a translation, and a translation is the wrong thing to
    /// keep evidence in.
    static func diagnostic(_ error: any Error) -> String {
        let error = error as NSError
        return "\(error.domain) code \(error.code) (\(error.localizedDescription))"
    }

    /// Whether this failure is the absence of a usable pairing rather than a
    /// fault. Callers use it to report a setup step instead of blaming the
    /// device's protocol support.
    static func isPairingFailure(_ error: any Error) -> Bool {
        let error = error as NSError
        switch error.domain {
        case CBATTErrorDomain:
            switch CBATTError.Code(rawValue: error.code) {
            case .insufficientEncryption, .insufficientAuthentication,
                 .insufficientAuthorization, .insufficientEncryptionKeySize:
                return true
            default:
                return false
            }
        case CBErrorDomain:
            switch CBError.Code(rawValue: error.code) {
            case .peerRemovedPairingInformation, .encryptionTimedOut,
                 .tooManyLEPairedDevices:
                return true
            default:
                return false
            }
        default:
            return false
        }
    }
}
