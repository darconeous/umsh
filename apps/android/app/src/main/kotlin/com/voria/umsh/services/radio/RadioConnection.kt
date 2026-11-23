package com.voria.umsh.services.radio

import com.voria.umsh.core.MobileRadioDriver

/**
 * A companion radio's transport and the plain commands it takes.
 *
 * The mesh is not here: the core holds [driver] and runs the mesh session
 * over it, and the radio's state reaches the screens only through the core.
 * What stays is the link itself and the commands a person gives the radio.
 * The host owns one at a time.
 */
interface RadioConnection {
    val kind: RadioKind

    /** The transport's identifier for this radio; the registry's `linkId`. */
    val linkId: String

    /** Handed to `core.useRadio`. */
    val driver: MobileRadioDriver

    /** The user asked: the recovery budget starts over, and the standing intent is set. */
    suspend fun connect()

    /** The standing intent, at start: no new recovery budget. */
    suspend fun autoConnect()

    /** This phone's host key is cleared from the radio; the link stays as it is. Returns within about 2 s. */
    suspend fun releaseHost()

    /** This phone's host key is cleared from the radio, the link goes down, and nothing reconnects. */
    suspend fun disconnect()

    /**
     * As [disconnect], and the radio is no longer remembered: what the
     * platform holds for it (its association, and on API 36+ its bond) goes
     * too, unless [keepBinding].
     */
    suspend fun forget(keepBinding: Boolean = false)

    /** The radio power-cycles and keeps what it saved. Throws `MobileRadioException`. */
    suspend fun restart()

    /** The radio erases everything and reboots blank. Throws `MobileRadioException`. */
    suspend fun factoryReset()

    /** Final: the driver stops and the link closes. Blocks briefly; never on the main thread. */
    fun close()
}

/** What a connection tells the host that owns it. */
fun interface RadioConnectionEvents {
    /**
     * The radio erased itself (a factory reset), and its link has since
     * dropped: the binding is gone, and the host lets the connection go.
     */
    fun bindingDropped(connection: RadioConnection)
}

/** Makes the connection a bound radio names; null for a kind this build cannot reach. */
fun interface RadioLinkFactory {
    fun make(radio: BoundRadio, registry: RadioRegistry, events: RadioConnectionEvents): RadioConnection?
}

/**
 * What the platform holds for a radio beyond the link: its companion
 * association, and on API 36+ the system bond, which only the association
 * can remove ([CompanionAssociations]).
 */
fun interface RadioBindings {
    /** Remove the bond where Android allows it (API 36+), then the association [associationId]. */
    fun release(associationId: String)

    companion object {
        val None = RadioBindings { }
    }
}
