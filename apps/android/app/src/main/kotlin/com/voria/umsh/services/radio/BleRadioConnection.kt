package com.voria.umsh.services.radio

import com.voria.umsh.core.MobileRadioProblem
import com.voria.umsh.core.MobileRadioTransportPhase
import com.voria.umsh.services.background.ReconnectPolicy
import com.voria.umsh.services.background.ReconnectStrategy
import com.voria.umsh.services.mobilecore.AppLog
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.launch

/**
 * A companion radio over Bluetooth LE: the bound radio, reached at the
 * address Android reports for it ([BoundRadio.linkId]), one [BleRadioLink]
 * attachment at a time.
 *
 * While the radio is wanted, a lost link comes back by itself (§7.2):
 * Reconnecting, through Android's background connect (`autoConnect`),
 * which resolves the radio's rotating address through the bond, after a
 * short backoff. That goes on for the reconnect window
 * ([ReconnectPolicy]); past it, the strategy decides. Waiting keeps the
 * background connect armed and says so; Presence closes the link and
 * leaves the radio to Android's companion presence, whose wake comes back
 * here as [autoConnect]. A connect the user asks for tries directly first,
 * with a window of its own. Bluetooth off, or Nearby devices withdrawn,
 * rests the link as Unavailable until both are back, and the radio is
 * sought again then.
 *
 * A fault the driver gives up on rests the link failed, and the standing
 * intent is cleared in the registry ([RadioDriverAdapter]): nothing but
 * the user's Reconnect brings it back, not a wake, and not a later process.
 *
 * A radio just found ([pairing]) is bonded once connected; a first
 * pairing whose link will not come up is not retried in the background,
 * where an unbonded radio's private address could never be resolved: it
 * gets one more direct try (none when nothing answered there at all),
 * then the attempt ends. Forgetting the radio,
 * or its link dropping after it erased itself, releases what Android
 * holds for it ([bindings]: its association, and on API 36+ its bond).
 */
class BleRadioConnection(
    radio: BoundRadio,
    registry: RadioRegistry,
    events: RadioConnectionEvents,
    private val bluetooth: StateFlow<BluetoothStatus>,
    /** Ports for the radio at a link ID; null when Android cannot address it. */
    private val ports: (linkId: String) -> GattPortFactory?,
    /**
     * The radio was just handed over by Connect a radio: its first
     * attachment bonds it. Any other connection only ever reaches a radio
     * already bonded, and one found unbonded has lost its bond.
     */
    pairing: Boolean,
    /** What Android holds for the radio besides the bond's use: its association. */
    private val bindings: RadioBindings = RadioBindings.None,
    /** The backoff's first step; tests shorten it. */
    private val firstRetryMs: Long = FIRST_RETRY_MS,
    /**
     * What follows the reconnect window, as it changes: applied when the
     * window ends, and at once to a radio already past it.
     */
    strategy: Flow<ReconnectStrategy> = flowOf(ReconnectStrategy.Waiting),
    /**
     * A monotonic clock in milliseconds that counts sleep (the app's:
     * `elapsedRealtime`). The window's end is judged by it; the executor's
     * delays do not count sleep, so the check is made again every
     * [windowRecheckMs] while a window runs.
     */
    private val clock: () -> Long = { System.nanoTime() / 1_000_000 },
    /** The reconnect window; tests shorten it. */
    windowMs: Long = ReconnectPolicy.WINDOW_MS,
    /** The longest a window's check waits while awake: how late a window that ended in sleep closes. Tests shorten it. */
    private val windowRecheckMs: Long = WINDOW_RECHECK_MS,
) : RadioDriverAdapter(RadioKind.Ble, radio.linkId, registry, events, radio.name) {
    private val associationId: String? = radio.associationId

    private val scheduler = object : LinkScheduler {
        override fun post(block: () -> Unit) {
            this@BleRadioConnection.post(block)
        }

        override fun schedule(delayMs: Long, block: () -> Unit) {
            postDelayed(delayMs, block)
        }
    }

    private val link = BleRadioLink(scheduler, LinkEvents())

    /** Watches the phone's Bluetooth and the strategy off the executor; posts each change onto it. */
    private val watcher = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    // Executor-confined.

    /** The standing intent: the radio is wanted, and comes back when it goes. */
    private var wanted = false

    /**
     * The driver gave up on a fault: only the user's connect starts again,
     * never the standing intent. Covers this process until the registry's
     * cleared intent is read back.
     */
    private var restingAfterFault = false
    private var status: BluetoothStatus = bluetooth.value

    /** What follows the window, as last heard; Waiting until the first is. */
    private var strategy = ReconnectStrategy.Waiting
    private var retryDelayMs = firstRetryMs

    /** Until the first attachment is ready: it may bond. */
    private var pairing = pairing

    /** Links a first pairing lost before they were ready. */
    private var pairingLosses = 0

    /** Bumped by each scheduled reconnect and by anything that supersedes one. */
    private var retryTicket = 0L

    /** The reconnect window: where the seeking stands, and when it ends. */
    private val policy = ReconnectPolicy(clock, windowMs)

    /** Bumped by each window check scheduled and by anything that ends the window. */
    private var windowTicket = 0L

    init {
        adopt()
        post { reportTransport(MobileRadioTransportPhase.IDLE, radioName) }
        watcher.launch {
            bluetooth.collect { status -> post { bluetoothChanged(status) } }
        }
        watcher.launch {
            strategy.distinctUntilChanged().collect { strategy -> post { strategyChanged(strategy) } }
        }
    }

    override fun startLink(userInitiated: Boolean) {
        if (!userInitiated && restingAfterFault) {
            AppLog.i(TAG, "ble: resting after a fault; only the user's connect brings it back")
            return
        }
        wanted = true
        if (userInitiated) {
            retryDelayMs = firstRetryMs
            restingAfterFault = false
        }
        // The user, or a wake for a radio left to presence: a new window.
        val fresh = userInitiated || policy.seeking == ReconnectPolicy.Seeking.Parked
        if (link.isOpen) {
            if (fresh && status.usable && !pairing) {
                startWindow(lost = false, fresh = true)
                if (link.phase == RadioLinkLifecycle.Phase.Connecting) reportTransport(policy.connectingPhase(), radioName)
            }
            return
        }
        retryTicket += 1
        if (!status.usable) {
            unavailable()
            return
        }
        if (fresh) AppLog.i(TAG, "ble: seeking the radio (${if (userInitiated) "asked" else "woken"})")
        startWindow(lost = false, fresh = fresh)
        open(autoConnect = !userInitiated)
    }

    override fun stopLink() {
        wanted = false
        retryTicket += 1
        endSeeking()
        link.close()
        reportTransport(MobileRadioTransportPhase.IDLE, radioName)
    }

    override fun linkSend(frame: ByteArray, rawTransactionId: UByte?) = link.send(frame, rawTransactionId)

    override fun linkResetFraming() = link.resetFraming()

    override fun linkInvalidate(retrying: Boolean) {
        val wasOpen = link.isOpen
        link.close()
        if (wasOpen) linkDropped()
        if (retrying && wanted) {
            seekAgain()
        } else {
            // Giving up stops the reconnects too: the driver has just
            // declared this radio unusable, and only the user brings it back.
            if (!retrying) {
                wanted = false
                restingAfterFault = true
            }
            retryTicket += 1
            endSeeking()
            reportTransport(MobileRadioTransportPhase.IDLE, radioName)
        }
    }

    override fun linkAbandonBinding() {
        // The radio is erasing itself; the link stays up so the command goes out.
        wanted = false
        retryTicket += 1
        endSeeking()
    }

    override fun linkDidEnterDfu() {
        wanted = false
        retryTicket += 1
        endSeeking()
        link.close()
        reportTransport(MobileRadioTransportPhase.IDLE, radioName)
    }

    override fun linkDidAttach() {
        // The address it attached at is the one bound (§7.1 step 5): the
        // scan's device, whose address Android keeps for the bond.
        AppLog.i(TAG, "ble: attached; the radio is this phone's")
        writeRegistry { registry.attached(linkId) }
    }

    override suspend fun releaseBinding() {
        val id = associationId ?: return
        // The bond first: removing it needs the association.
        bindings.release(id)
    }

    override fun linkClosed() {
        watcher.cancel()
    }

    private fun open(autoConnect: Boolean) {
        if (!status.usable) {
            unavailable()
            return
        }
        val factory = ports(linkId) ?: run {
            AppLog.w(TAG, "ble: no device at the bound address")
            endSeeking()
            reportTransport(MobileRadioTransportPhase.FAILED, radioName, RadioTransportProblem.SavedRadioUnknown.problem)
            return
        }
        AppLog.i(TAG, "ble: connecting (${if (autoConnect) "background" else "direct"})")
        link.open(factory, autoConnect = autoConnect, bond = pairing)
    }

    private fun unavailable() {
        if (link.isOpen) {
            link.close()
            linkDropped()
        }
        retryTicket += 1
        // No window runs while the medium is gone; one starts when it is back.
        endSeeking()
        reportTransport(
            if (wanted) MobileRadioTransportPhase.UNAVAILABLE else MobileRadioTransportPhase.IDLE,
            radioName,
            status.problem.takeIf { wanted },
        )
    }

    private fun bluetoothChanged(now: BluetoothStatus) {
        val before = status
        status = now
        if (before.usable == now.usable && before.problem == now.problem) return
        if (!now.usable) {
            unavailable()
        } else if (wanted && !link.isOpen) {
            // Back on: a fresh budget and window, and the radio is sought at once.
            retryDelayMs = firstRetryMs
            retryTicket += 1
            startWindow(lost = false, fresh = true)
            open(autoConnect = true)
        }
    }

    /**
     * The strategy changed (the Developer switch). A radio already past the
     * window takes the new one at once: armed again under Waiting, closed
     * under Presence. One attaching is left to settle.
     */
    private fun strategyChanged(now: ReconnectStrategy) {
        if (now == strategy) return
        strategy = now
        if (!wanted) return
        when (policy.strategyChanged(now)) {
            ReconnectPolicy.Seeking.Waiting -> if (!link.isOpen && status.usable) {
                AppLog.i(TAG, "ble: past the window; now waiting, with a background connect")
                retryDelayMs = firstRetryMs
                retryTicket += 1
                open(autoConnect = true)
            }
            ReconnectPolicy.Seeking.Parked -> if (!link.isOpen || link.phase == RadioLinkLifecycle.Phase.Connecting) {
                AppLog.i(TAG, "ble: past the window; now left to presence")
                retryTicket += 1
                link.close()
                reportTransport(MobileRadioTransportPhase.WAITING_FOR_RADIO, radioName)
            }
            else -> Unit
        }
    }

    /** Seek the radio, starting a window unless one runs; [lost]: the attachment just went. */
    private fun startWindow(lost: Boolean, fresh: Boolean) {
        val endsAt = policy.begin(lost, fresh) ?: return
        val ticket = ++windowTicket
        AppLog.i(TAG, "ble: ${policy.seeking} for up to ${(endsAt - clock()) / 1000} s")
        scheduleWindowCheck(ticket, endsAt)
    }

    /**
     * Check the window at its end, by [clock]. The delay runs only while
     * the phone is awake, so a phone asleep through the end would hold the
     * window open for as long again awake: the check comes at least every
     * [windowRecheckMs] of waking time, and the first after the end
     * closes it. Never a wake of its own.
     */
    private fun scheduleWindowCheck(ticket: Long, endsAt: Long) {
        postDelayed((endsAt - clock()).coerceIn(0, windowRecheckMs)) {
            if (ticket != windowTicket) return@postDelayed
            if (policy.inWindow && clock() < endsAt) scheduleWindowCheck(ticket, endsAt) else windowCheck()
        }
    }

    /** No longer seeking: attached, deliberately down, given up, or Bluetooth gone. */
    private fun endSeeking() {
        windowTicket += 1
        policy.stop()
    }

    /** The window's time is up: the strategy takes over, unless an attempt is past connecting. */
    private fun windowCheck() {
        if (!wanted || pairing || !policy.windowPassed()) return
        if (link.isOpen && link.phase != RadioLinkLifecycle.Phase.Connecting) {
            // Connected and attaching: that attempt settles it. Its loss ends the window.
            return
        }
        windowEnded()
    }

    private fun windowEnded() {
        when (policy.windowEnded(strategy)) {
            ReconnectPolicy.Seeking.Parked -> {
                AppLog.i(TAG, "ble: not back within the window; left to presence")
                retryTicket += 1
                link.close()
                reportTransport(MobileRadioTransportPhase.WAITING_FOR_RADIO, radioName)
            }
            ReconnectPolicy.Seeking.Waiting -> {
                AppLog.i(TAG, "ble: not back within the window; waiting, with a background connect")
                reportTransport(MobileRadioTransportPhase.WAITING_FOR_RADIO, radioName)
                if (!link.isOpen) reconnectLater()
            }
            else -> Unit
        }
    }

    /** The link went or failed while wanted: past the window the strategy decides, otherwise it is sought again. */
    private fun seekAgain() {
        if (policy.windowPassed()) {
            windowEnded()
            return
        }
        // Lost from attached starts a window; inside one, it goes on.
        startWindow(lost = true, fresh = false)
        reconnectLater()
    }

    /** A background connect after the backoff, reporting where the seeking stands meanwhile. */
    private fun reconnectLater() {
        reportTransport(policy.connectingPhase(), radioName)
        val ticket = ++retryTicket
        val delay = retryDelayMs
        retryDelayMs = (retryDelayMs * 2).coerceAtMost(MAX_RETRY_MS)
        postDelayed(delay) {
            if (ticket != retryTicket || !wanted || link.isOpen) return@postDelayed
            open(autoConnect = true)
        }
    }

    private inner class LinkEvents : BleRadioLink.Sink {
        override fun phase(phase: MobileRadioTransportPhase) {
            // Not connected yet: where the seeking stands says what that is.
            reportTransport(if (phase == MobileRadioTransportPhase.CONNECTING) policy.connectingPhase() else phase, radioName)
        }

        override fun ready() {
            retryDelayMs = firstRetryMs
            pairing = false
            endSeeking()
            // The address is the bound radio's: whatever answers there is it.
            reportLinkReady(boundRadio = true)
        }

        override fun received(frame: ByteArray) = reportReceived(frame)

        override fun writesFailed(rawTransactionIds: List<UByte>, problem: MobileRadioProblem) =
            reportWritesFailed(rawTransactionIds, problem)

        override fun fault(problem: MobileRadioProblem) = reportFault(problem)

        override fun bondFailed() {
            // The person declined, or let the dialog lapse: no reconnect
            // asks again. The driver's invalidate then rests the link,
            // failed with the refusal; only the user starts it again.
            wanted = false
            reportFault(RadioTransportProblem.AttachmentRefused.problem)
        }

        override fun lost(status: Int) {
            linkDropped()
            if (pairing && wanted && this@BleRadioConnection.status.usable) {
                // A radio being paired has no bond to resolve its address by:
                // a background connect would wait for ever. Once more directly,
                // then the attempt is over.
                pairingLosses += 1
                // A connection that timed out found nothing at the address the
                // scan heard (its pairing window closed, and with it the
                // address): another try would only wait as long again.
                if (pairingLosses < PAIRING_TRIES && status != CONNECTION_TIMEOUT) {
                    AppLog.i(TAG, "ble: pairing link lost (status $status); trying again")
                    reportTransport(MobileRadioTransportPhase.CONNECTING, radioName)
                    val ticket = ++retryTicket
                    postDelayed(firstRetryMs) {
                        if (ticket == retryTicket && wanted && !link.isOpen) open(autoConnect = false)
                    }
                } else {
                    AppLog.w(TAG, "ble: pairing link lost (status $status); giving up")
                    wanted = false
                    // Nothing at the address is no radio found there: its
                    // pairing window has closed. Anything else is a connection
                    // that failed, the radio perhaps off or out of range.
                    val problem = if (status == CONNECTION_TIMEOUT) {
                        RadioTransportProblem.NoRadioFound
                    } else {
                        RadioTransportProblem.ConnectionFailed
                    }
                    reportFault(problem.problem)
                }
            } else if (wanted && this@BleRadioConnection.status.usable) {
                seekAgain()
            } else if (!this@BleRadioConnection.status.usable) {
                unavailable()
            } else {
                reportTransport(MobileRadioTransportPhase.IDLE, radioName)
            }
        }
    }

    private companion object {
        const val TAG = "umsh.radio"
        const val FIRST_RETRY_MS = 1_000L

        /** Direct connects a first pairing gets before it gives up. */
        const val PAIRING_TRIES = 2

        /** `GATT_CONNECTION_TIMEOUT` (0x93): nothing answered at the address. */
        const val CONNECTION_TIMEOUT = 147

        /** As iOS's `scheduleReconnect`. */
        const val MAX_RETRY_MS = 5_000L

        const val WINDOW_RECHECK_MS = 10_000L
    }
}
