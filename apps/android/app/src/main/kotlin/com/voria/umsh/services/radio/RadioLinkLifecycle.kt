package com.voria.umsh.services.radio

/**
 * The phases of one attachment (iOS `RadioLinkLifecycle`): which GATT
 * callbacks it takes, and moves only from the phase expected. Stale
 * callbacks from an earlier attachment never reach it: [BleRadioLink] drops
 * them by their port. Deadlines are per operation, in [GattQueue].
 *
 * Confined to the connection's executor.
 */
class RadioLinkLifecycle {
    enum class Phase { Idle, Connecting, Services, Characteristics, Subscribing, Ready }

    var phase: Phase = Phase.Idle
        private set

    /** Whether a GATT callback belongs to this attachment's phases at all. */
    val acceptsGatt: Boolean
        get() = when (phase) {
            Phase.Services, Phase.Characteristics, Phase.Subscribing, Phase.Ready -> true
            Phase.Idle, Phase.Connecting -> false
        }

    fun begin() {
        phase = Phase.Connecting
    }

    /** Move on only from [from]; false, and nothing changes, from any other phase. */
    fun advance(from: Phase, to: Phase): Boolean {
        if (phase != from) return false
        phase = to
        return true
    }

    fun clear() {
        phase = Phase.Idle
    }
}
