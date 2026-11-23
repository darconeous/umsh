package com.voria.umsh.services.background

import com.voria.umsh.services.mobilecore.AppLog
import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.RadioKind
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.launch

/** Where Android observes a radio's presence: [CompanionAssociations] in the app, a recording fake in tests. */
interface PresenceObservations {
    /** The phone has companion-device support: presence can be observed at all. */
    val available: Boolean

    /** Every association the app holds, by ID: the ones not observed are told to stop. */
    fun associationIds(): Collection<String>

    fun observe(associationId: String, observe: Boolean)
}

/**
 * Which radio Android watches for (§7.3): the bound Bluetooth radio, with
 * its association, while it is wanted and the Presence strategy is in use;
 * no other. Follows the registry, so it is right from every process start
 * on: observation starts once a radio is bound and wanted, and stops on
 * Disconnect (and DFU), a fault the driver gave up on, Forget, a factory
 * reset, choosing another radio, and the Developer switch to Waiting: each
 * leaves the radio unwanted or unbound. Bluetooth off changes nothing: the
 * observation stays registered, and Android's own scan resumes with it.
 */
class RadioPresence(
    private val observations: PresenceObservations,
    bound: Flow<BoundRadio?>,
    preferred: Flow<ReconnectStrategy>,
    scope: CoroutineScope,
) {
    init {
        if (observations.available) {
            scope.launch {
                combine(bound, preferred) { radio, strategy -> observedFor(radio, strategy, available = true) }
                    .distinctUntilChanged()
                    .collect(::follow)
            }
        }
    }

    private fun follow(observed: String?) {
        // Every other association stops: one released by choosing another
        // radio, or left from an earlier process, is never watched for.
        for (id in observations.associationIds()) {
            if (id != observed) observations.observe(id, observe = false)
        }
        if (observed != null) observations.observe(observed, observe = true)
        if (observed == null) AppLog.i(TAG, "presence: no radio observed")
    }

    companion object {
        private const val TAG = "umsh.presence"

        /** Pure, for the tests: the association observed for [radio] under [preferred] on a phone where presence is [available]. */
        fun observedFor(radio: BoundRadio?, preferred: ReconnectStrategy, available: Boolean): String? {
            // One being added is watched once it has attached.
            if (!available || radio == null || radio.kind != RadioKind.Ble || !radio.autoConnect || radio.pending != null) return null
            val strategy = ReconnectStrategy.effective(preferred, available, radio)
            return radio.associationId.takeIf { strategy == ReconnectStrategy.Presence }
        }
    }
}
