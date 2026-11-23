package com.voria.umsh.services.radio

import com.voria.umsh.core.MobileRadioProblem

/**
 * A failure a transport reports in its own terms. The driver carries
 * problems as codes, never text, so each travels as a code under this app's
 * domain and is worded where it is shown ([RadioProblemWords]).
 *
 * The codes are iOS's (`RadioTransportProblem.swift`), so logs and the core
 * read the same number the same way on both. Never renumber; the codes iOS
 * alone produces (its accessory setup) are kept so none is reused.
 */
enum class RadioTransportProblem(val code: Long) {
    // Bluetooth attachment
    UnsendableFrame(1),
    LinkLost(2),
    WriteUnacknowledged(3),
    AttachmentIncomplete(4),
    ServiceMissing(5),
    ServiceIncompatible(6),
    AttachmentRefused(7),
    EndpointUnwritable(8),
    WriteModeUnsupported(9),
    ConnectionFailed(10),
    NoRadioFound(11),
    NoSavedRadio(12),
    SavedRadioUnknown(13),
    RemovalFailed(14),

    // Bluetooth itself
    BluetoothUnauthorized(15),
    BluetoothUnsupported(16),
    BluetoothOff(17),
    BluetoothResetting(18),
    BluetoothStarting(19),
    BluetoothUnavailable(20),

    // iOS's accessory setup; never produced here
    AccessoriesLoading(21),
    AccessorySetupOpen(22),
    AccessorySetupUnfinished(23),
    AccessoryNeeded(24),
    AccessoriesUnavailable(25),

    // A bridged radio
    BridgeUnreachable(26),
    BridgeWaiting(27),
    BridgeFailed(28),
    BridgeClosed(29),

    // The local network radio
    LocalRadioStopped(30),
    LocalRadioNotRunning(31),
    LocalRadioClosed(32),
    LocalRadioInUse(33),
    LocalRadioUnavailable(34),

    // An administered radio
    AccessRemoved(35),
    ConnectionIncomplete(36),
    ;

    val problem: MobileRadioProblem get() = MobileRadioProblem.Transport(DOMAIN, code)

    companion object {
        const val DOMAIN = "com.voria.umsh.radio-transport"

        fun of(problem: MobileRadioProblem): RadioTransportProblem? =
            (problem as? MobileRadioProblem.Transport)
                ?.takeIf { it.domain == DOMAIN }
                ?.let { transport -> entries.firstOrNull { it.code == transport.code } }
    }
}
