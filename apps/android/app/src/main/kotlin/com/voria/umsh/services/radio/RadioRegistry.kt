package com.voria.umsh.services.radio

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first

/** How a companion radio is reached. */
enum class RadioKind {
    Ble,

    /** Debug builds: a `umsh-bridge` host interface over TCP. */
    Tcp,

    /** Debug builds: the staged mesh's radio, which is never remembered. */
    Staging,
}

/**
 * The live radio this phone is bound to, as remembered across launches:
 * iOS's `connectedUUID`, `shouldAutoConnect` and `deviceName`.
 */
data class BoundRadio(
    /** [RadioKind.Ble] or [RadioKind.Tcp]; staging is never bound. */
    val kind: RadioKind,
    /** BLE: the address Android reports for the bonded radio, as reported. TCP: `host:port`. */
    val linkId: String,
    /** The CompanionDeviceManager association (API 31–32: its MAC string). */
    val associationId: String? = null,
    /** The model ID (`docs/hardware/boards.json`) recorded at pairing. */
    val modelId: Int? = null,
    /** The last name the radio reported for itself. */
    val name: String? = null,
    /** The standing intent to connect: false after Disconnect. */
    val autoConnect: Boolean = true,
    /**
     * Bound by Connect a radio or Choose a radio, and not yet attached:
     * the attempt is under way. Null once it has attached, and for a radio
     * bound any other way. One found at a process start was cut off by the
     * process ending, and is undone rather than connected.
     */
    val pending: PendingBinding? = null,
)

/** What undoing an attempt cut off by the process ending leaves of its association. */
enum class PendingBinding {
    /** Made for the attempt: released with it. */
    NewAssociation,

    /** The radio's from before the attempt: kept. */
    KnownAssociation,
}

/**
 * Which live radio this phone is bound to. Kept in the app's preferences,
 * so Start over clears it with the rest; Erase identity keeps it, and the
 * new identity claims the radio.
 *
 * Every write that a connection makes names the radio it is about, and
 * changes nothing when another radio has been bound since: a connection
 * being retired never edits its successor's entry.
 */
interface RadioRegistry {
    /** The bound radio, every time it changes; null when there is none. */
    val bound: Flow<BoundRadio?>

    suspend fun bound(): BoundRadio? = bound.first()

    /** Remember [radio] as the bound one, replacing any other. */
    suspend fun bind(radio: BoundRadio)

    suspend fun setAutoConnect(linkId: String, enabled: Boolean)

    /** [linkId] attached: it is wanted, and no longer an attempt under way. */
    suspend fun attached(linkId: String)

    suspend fun setName(linkId: String, name: String)

    /** Forget the bound radio, if it is still [linkId]. */
    suspend fun clear(linkId: String)
}
