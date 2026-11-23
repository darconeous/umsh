package com.voria.umsh.services.radio

import com.voria.umsh.app.AppCoreHost
import com.voria.umsh.app.HostState
import com.voria.umsh.app.RadioChoice
import com.voria.umsh.core.MobileRadioPhase
import com.voria.umsh.features.onboarding.ConnectFailure
import com.voria.umsh.services.mobilecore.AppLog
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Connects a radio Connect a radio or Choose a radio found (§7.1, §3.4):
 *
 * 1. Android's confirmation that the app may manage it (CompanionDeviceManager),
 *    unless it is already associated, which needs none. Declining changes
 *    nothing: the radio held until now is still held.
 * 2. The host releases the radio it holds (its host key cleared on it),
 *    lets it go, and binds this one; the released radio stays associated.
 * 3. The radio connects over LE and bonds (the system's pairing dialog),
 *    attaches and is claimed; this waits for it to carry this phone.
 *
 * One that does not come up is let go again, and a failed first pairing
 * takes its association and (API 36+) its bond with it, so it leaves
 * nothing behind; one associated before the attempt keeps its
 * association, unless it refused this phone's keys. Leaving the page
 * before the radio came up does the same.
 */
class HostRadioConnector(
    private val host: AppCoreHost,
    private val associations: RadioAssociations,
) : ScannedRadioConnector {
    override suspend fun connect(radio: HeardRadio, page: ConfirmationPage): ConnectOutcome {
        val address = radio.address
        val known = associations.associationFor(address)
        val associationId = when {
            known != null -> {
                AppLog.i(TAG, "connect a radio: already associated")
                known
            }
            // A phone without companion device setup connects without one.
            !associations.available -> null
            else -> when (val made = associations.associate(radio.device, page)) {
                is Association.Made -> {
                    if (made.address != null && made.address != address) {
                        AppLog.w(TAG, "connect a radio: associated at another address than the one heard")
                    }
                    AppLog.i(TAG, "connect a radio: associated")
                    made.id
                }
                Association.Declined -> return ConnectOutcome.Declined
                Association.NoDevice -> return ConnectOutcome.Failed(ConnectFailure.PairingRemoved)
                Association.Failed -> return ConnectOutcome.Failed(ConnectFailure.ConnectFailed)
            }
        }
        // Kept by an attempt that fails: it was this phone's before.
        val keepBinding = known != null
        ScannedDevices.offer(address, radio.device)
        val choice = host.connectRadio(
            BoundRadio(
                RadioKind.Ble,
                address,
                associationId = associationId,
                modelId = radio.advertisement.modelId,
                name = radio.advertisement.name,
                // Until it attaches: a process that ends first leaves it to be undone.
                pending = if (keepBinding) PendingBinding.KnownAssociation else PendingBinding.NewAssociation,
            ),
        )
        try {
            choice.bound.join()
            val runtime = (host.state.value as? HostState.Ready)?.runtime
                ?: return letGo(choice, ConnectFailure.ConnectFailed, null, keepBinding)
            // The bind did not take (no live core, or it would not take the
            // radio): nothing will come up to wait for.
            val held = host.radio.value
            if (held == null || held.kind != RadioKind.Ble || held.linkId != address) {
                return letGo(choice, ConnectFailure.ConnectFailed, null, keepBinding)
            }
            val outcome = withTimeoutOrNull(ATTACH_TIMEOUT_MS) {
                runtime.radio.first { shown ->
                    shown != null && shown.linkId == address && (shown.carriesThisPhone || settled(shown))
                }
            }
            if (outcome?.carriesThisPhone == true) return ConnectOutcome.Connected
            val problem = outcome?.problem?.let(RadioTransportProblem::of)
            val refused = problem == RadioTransportProblem.AttachmentRefused
            val failure = when {
                outcome == null -> ConnectFailure.ConnectFailed
                outcome.phase == MobileRadioPhase.UNAVAILABLE -> ConnectFailure.BluetoothUnavailable
                refused -> ConnectFailure.PairingRemoved
                // Nothing answered at the address its pairing window
                // advertised: the window closed (a new address), most likely
                // under the confirmation, and the radio has to be added again.
                problem == RadioTransportProblem.NoRadioFound -> ConnectFailure.PairingRemoved
                else -> ConnectFailure.ConnectFailed
            }
            // A radio that refused this phone's keys has dropped its pairing:
            // what this phone kept for it is dead, and adding it again needs
            // a new association (and on API 36+ a new bond), so it goes too.
            return letGo(choice, failure, outcome?.phase, keepBinding && !refused)
        } catch (cancelled: CancellationException) {
            // The page went before the radio came up: leaving it is
            // calling the attempt off, so the radio is let go here too,
            // once the bind itself has finished, unless another choice has
            // been made since.
            withContext(NonCancellable) {
                choice.bound.join()
                AppLog.i(TAG, "connect a radio: left before attaching; letting it go")
                host.forgetRadio(keepBinding, choice).join()
            }
            throw cancelled
        } finally {
            // The bind takes the scanned device; one that never bound
            // leaves nothing for a later connection to take by mistake.
            ScannedDevices.discard(address, radio.device)
        }
    }

    private suspend fun letGo(
        choice: RadioChoice,
        failure: ConnectFailure,
        phase: MobileRadioPhase?,
        keepBinding: Boolean,
    ): ConnectOutcome {
        AppLog.i(TAG, "connect a radio: not attached ($phase); letting it go")
        host.forgetRadio(keepBinding, choice).join()
        return ConnectOutcome.Failed(failure)
    }

    /** At rest short of attached: the attempt is over. */
    private fun settled(radio: RadioSnapshot): Boolean = when (radio.phase) {
        MobileRadioPhase.FAILED, MobileRadioPhase.UNAVAILABLE -> true
        MobileRadioPhase.IDLE -> radio.problem != null
        else -> false
    }

    private companion object {
        const val TAG = "umsh.radio"

        /** Long enough for the pairing dialog and a passkey typed in. */
        const val ATTACH_TIMEOUT_MS = 90_000L
    }
}
