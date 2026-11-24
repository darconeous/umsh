package com.voria.umsh.services.radio

import android.bluetooth.BluetoothDevice
import android.companion.CompanionDeviceManager
import android.content.IntentSender
import androidx.activity.result.ActivityResult
import com.voria.umsh.app.AppCoreHost
import com.voria.umsh.app.AppPaths
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.CoreKind
import com.voria.umsh.app.HostState
import com.voria.umsh.app.MemoryVaults
import com.voria.umsh.app.SendOutcome
import com.voria.umsh.app.VaultLog
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.core.MobileRadioPhase
import com.voria.umsh.features.onboarding.ConnectFailure
import com.voria.umsh.services.background.RadioPresence
import com.voria.umsh.services.background.ReconnectPolicy
import com.voria.umsh.services.background.ReconnectStrategy
import com.voria.umsh.services.preferences.AppPreferences
import java.time.Clock
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * A radio over Bluetooth end to end, with no Android Bluetooth (§4.3): the
 * live core's driver through [BleRadioConnection] and [BleRadioLink] to a
 * real device session behind [FakeRadioPeripheral]'s GATT surface.
 */
class BleAttachTest {
    @get:Rule val temp = TemporaryFolder()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private lateinit var peripheral: FakeRadioPeripheral
    private lateinit var host: AppCoreHost
    private lateinit var preferences: AppPreferences
    private val bluetooth = MutableStateFlow(BluetoothStatus.Ready)
    private val address = "C0:FF:EE:00:00:01"
    private val associations = FakeAssociations()

    /** CompanionDeviceManager as the tests script it: what it answers, and what it was asked. */
    private class FakeAssociations : RadioAssociations {
        override val available = true
        val known = ConcurrentHashMap<String, String>()
        @Volatile var answer: Association = Association.Made("7", null)
        val asked = AtomicInteger()
        val released: MutableList<String> = Collections.synchronizedList(mutableListOf())

        override fun associationFor(address: String): String? = known[address]

        override suspend fun associate(device: BluetoothDevice, page: ConfirmationPage): Association {
            asked.incrementAndGet()
            return answer
        }

        override fun release(associationId: String) {
            released += associationId
        }
    }

    /** No page on screen: the scripted associations never ask one. */
    private object NoPage : ConfirmationPage {
        override val companionDevices: CompanionDeviceManager? = null

        override suspend fun confirm(sender: IntentSender): ActivityResult? = null
    }

    /** A radio no link reaches: the bind never takes it. */
    @Volatile private var noLinkFor: String? = null

    /** What follows the reconnect window, and how long it is; tests shorten it. */
    private val strategy = MutableStateFlow(ReconnectStrategy.Waiting)
    private var windowMs = ReconnectPolicy.WINDOW_MS

    /** The connection's sleep-counting clock: real time, plus what a test says the phone slept. */
    private val slept = java.util.concurrent.atomic.AtomicLong()
    private var windowRecheckMs = 10_000L

    private lateinit var paths: AppPaths
    private val vaults = MemoryVaults(VaultLog())

    private fun start(): AppCoreHost {
        peripheral = FakeRadioPeripheral(temp.newFolder("radio"))
        paths = AppPaths(temp.newFolder(), temp.newFolder())
        preferences = AppPreferences(paths.preferences, scope)
        host = newHost()
        return host
    }

    private fun newHost(): AppCoreHost {
        val links = RadioLinkFactory { radio, registry, events ->
            // Every radio here is bound as Connect a radio binds one: just found.
            if (radio.linkId == noLinkFor) return@RadioLinkFactory null
            BleRadioConnection(
                radio, registry, events, bluetooth, { peripheral }, pairing = true, bindings = associations, firstRetryMs = 50,
                strategy = strategy, clock = { System.nanoTime() / 1_000_000 + slept.get() }, windowMs = windowMs,
                windowRecheckMs = windowRecheckMs,
            )
        }
        return AppCoreHost(
            paths, vaults, preferences, { 65026u }, Clock.systemUTC(), MutableSharedFlow(), true, scope,
            radioLinks = links,
            bindings = associations,
        )
    }

    /** As a new process would: the host goes, and another comes up over the same files and radio. */
    private suspend fun newProcess(): AppRuntime {
        withTimeout(TIMEOUT) { host.shutdown() }
        host = newHost()
        return running()
    }

    @After
    fun tearDown() = runBlocking<Unit> {
        if (::host.isInitialized) withTimeout(TIMEOUT) { host.shutdown() }
        scope.cancel()
        if (::peripheral.isInitialized) peripheral.close()
    }

    private suspend fun running(): AppRuntime {
        host.ensureRuntime()
        val ready = withTimeout(TIMEOUT) {
            host.state.first { it is HostState.Ready && it.runtime.kind == CoreKind.Live }
        } as HostState.Ready
        withTimeout(TIMEOUT) { ready.runtime.lifecycle.first { it is MobileAppLifecycle.Running } }
        return ready.runtime
    }

    private suspend fun AppRuntime.radioWhere(predicate: (RadioSnapshot) -> Boolean): RadioSnapshot =
        withTimeout(TIMEOUT) { radio.first { it != null && predicate(it) }!! }

    private suspend fun connect(): AppRuntime {
        val runtime = running()
        host.connectRadio(BoundRadio(RadioKind.Ble, address, modelId = 2, name = "T1000-E 4F2A")).bound.join()
        return runtime
    }

    @Test
    fun aRadioAttachesAndCarriesThisPhone() = runBlocking<Unit> {
        start()
        val runtime = connect()
        val attached = runtime.radioWhere { it.carriesThisPhone }
        assertEquals(MobileRadioPhase.ATTACHED, attached.phase)
        assertTrue(peripheral.bonded)
        assertEquals(1, peripheral.opened.get())
    }

    @Test
    fun aChatFrameGoesOutToTheRadio() = runBlocking<Unit> {
        start()
        val runtime = connect()
        runtime.radioWhere { it.carriesThisPhone }
        // A private channel of the test's own: nothing a person listens on.
        val channel = runtime.core.createPrivateChannel("BleAttachTest")
        val conversation = runtime.openChannelConversation(channel).await()
        val text = "BleAttachTest frame"
        val before = peripheral.framesIn.size
        assertEquals(SendOutcome.Sent, runtime.send(conversation, text, forwardSecret = null).await())
        // A CMD_STR_SEND (9) to the radio, carrying more than the text: the
        // whole packet, sealed. Property polls and the like are not it.
        withTimeout(TIMEOUT) {
            while (
                peripheral.framesIn.drop(before).none { it.size > 2 + text.length && it[1] == CMD_STR_SEND }
            ) {
                delay(20)
            }
        }
    }

    /** The smallest MTU still carries every frame, in more segments. */
    @Test
    fun theDefaultMtuStillAttaches() = runBlocking<Unit> {
        start()
        peripheral.grantedMtu = RadioGatt.DEFAULT_MTU
        val runtime = connect()
        runtime.radioWhere { it.carriesThisPhone }
    }

    /** A link the radio drops comes back by itself, and the radio carries this phone again. */
    @Test
    fun aDroppedLinkReconnects() = runBlocking<Unit> {
        start()
        val runtime = connect()
        runtime.radioWhere { it.carriesThisPhone }
        peripheral.drop()
        runtime.radioWhere { !it.carriesThisPhone }
        runtime.radioWhere { it.carriesThisPhone }
        assertEquals(2, peripheral.opened.get())
    }

    /**
     * The radio lost this phone's keys: each attachment is refused, and
     * once the driver's budget is spent the link rests failed, saying so.
     */
    @Test
    fun aRefusedSubscriptionIsAttachmentRefused() = runBlocking<Unit> {
        start()
        peripheral.refuseCccd = true
        val runtime = connect()
        val failed = runtime.radioWhere { it.phase == MobileRadioPhase.FAILED }
        assertEquals(RadioTransportProblem.AttachmentRefused, failed.problem?.let(RadioTransportProblem::of))
        val tries = peripheral.opened.get()
        assertTrue(tries > 1)
        delay(500)
        assertEquals(tries, peripheral.opened.get())
    }

    /**
     * The person declines the system's pairing dialog: one bond attempt,
     * then the attempt ends, refused, with no reconnect asking again.
     */
    @Test
    fun aDeclinedBondEndsTheAttempt() = runBlocking<Unit> {
        start()
        peripheral.refuseBond = true
        val runtime = connect()
        val failed = runtime.radioWhere { it.phase == MobileRadioPhase.FAILED }
        assertEquals(RadioTransportProblem.AttachmentRefused, failed.problem?.let(RadioTransportProblem::of))
        delay(500)
        assertEquals(1, peripheral.bondAttempts.get())
        assertEquals(1, peripheral.opened.get())
    }

    /**
     * Android's bond went (the person removed it in Settings) after the
     * first pairing: reconnects are refused without ever asking to bond.
     */
    @Test
    fun aRemovedBondIsRefusedWithoutAsking() = runBlocking<Unit> {
        start()
        val runtime = connect()
        runtime.radioWhere { it.carriesThisPhone }
        peripheral.bonded = false
        peripheral.drop()
        val failed = runtime.radioWhere { it.phase == MobileRadioPhase.FAILED }
        assertEquals(RadioTransportProblem.AttachmentRefused, failed.problem?.let(RadioTransportProblem::of))
        assertEquals(1, peripheral.bondAttempts.get())
    }

    /** API 36: the radio forgets this phone's keys; the link ends refused, and nothing asks to bond. */
    @Test
    fun aLostBondIsAttachmentRefused() = runBlocking<Unit> {
        start()
        val runtime = connect()
        runtime.radioWhere { it.carriesThisPhone }
        peripheral.loseBond()
        val failed = runtime.radioWhere { it.phase == MobileRadioPhase.FAILED }
        assertEquals(RadioTransportProblem.AttachmentRefused, failed.problem?.let(RadioTransportProblem::of))
        assertEquals(1, peripheral.bondAttempts.get())
    }

    /** Leaving Connect a radio while the pairing dialog is up lets the radio go. */
    @Test
    fun leavingMidPairingLetsTheRadioGo() = runBlocking<Unit> {
        start()
        peripheral.holdBond = true
        val runtime = running()
        val heard = HeardRadio(
            unconstructed(),
            address,
            RadioAdvertisement(discoverable = true, modelId = 2, name = "T1000-E 4F2A", hasService = true),
        )
        val attempt = scope.launch { HostRadioConnector(host, associations).connect(heard, NoPage) }
        runtime.radioWhere { it.phase == MobileRadioPhase.PAIRING }
        attempt.cancel()
        attempt.join()
        withTimeout(TIMEOUT) {
            while (preferences.radioRegistry.bound() != null) delay(20)
        }
        // The association made for it goes with it.
        assertEquals(listOf("7"), associations.released)
        assertEquals(1, peripheral.bondAttempts.get())
        val opened = peripheral.opened.get()
        delay(500)
        assertEquals(opened, peripheral.opened.get())
    }

    // region Pairing: the association, then the radio (§7.1, §3.4)

    private fun heard(at: String = address) = HeardRadio(
        unconstructed(),
        at,
        RadioAdvertisement(discoverable = true, modelId = 2, name = "T1000-E 4F2A", hasService = true),
    )

    /** Allowed, then bonded and attached: bound with its association, which Forget releases. */
    @Test
    fun anAllowedRadioIsBoundWithItsAssociation() = runBlocking<Unit> {
        start()
        val runtime = running()
        assertEquals(ConnectOutcome.Connected, HostRadioConnector(host, associations).connect(heard(), NoPage))
        assertEquals(1, associations.asked.get())
        val bound = preferences.radioRegistry.bound()!!
        assertEquals("7", bound.associationId)
        assertEquals(2, bound.modelId)
        assertTrue(bound.autoConnect)
        runtime.radioWhere { it.carriesThisPhone }
        // Attached: no longer an attempt under way.
        withTimeout(TIMEOUT) { preferences.radioRegistry.bound.first { it?.pending == null } }
        assertTrue(associations.released.isEmpty())
        host.forgetRadio().join()
        assertEquals(listOf("7"), associations.released)
        assertNull(preferences.radioRegistry.bound())
    }

    /**
     * The process ended while a radio was still being added (after Allow,
     * before it attached): the next start undoes the attempt as the attempt
     * would have, rather than connecting a radio never finished. An
     * association made for it goes; one the radio had before stays.
     */
    @Test
    fun anAttemptTheProcessEndedInIsUndoneAtTheNextStart() = runBlocking<Unit> {
        start()
        preferences.radioRegistry.bind(
            BoundRadio(RadioKind.Ble, address, associationId = "7", modelId = 2, pending = PendingBinding.NewAssociation),
        )
        val runtime = running()
        assertNull(preferences.radioRegistry.bound())
        assertEquals(listOf("7"), associations.released)
        assertNull(host.radio.value)
        assertNull(runtime.radio.value?.linkId)
        assertEquals(0, peripheral.opened.get())

        preferences.radioRegistry.bind(
            BoundRadio(RadioKind.Ble, address, associationId = "5", modelId = 2, pending = PendingBinding.KnownAssociation),
        )
        newProcess()
        assertNull(preferences.radioRegistry.bound())
        assertEquals(listOf("7"), associations.released)
        assertEquals(0, peripheral.opened.get())
    }

    /** "Don't allow" changes nothing: the radio held until now is still held, and still carries this phone. */
    @Test
    fun aDeclinedConfirmationChangesNothing() = runBlocking<Unit> {
        start()
        val runtime = connect()
        runtime.radioWhere { it.carriesThisPhone }
        val held = host.radio.value
        val before = preferences.radioRegistry.bound()
        associations.answer = Association.Declined
        assertEquals(ConnectOutcome.Declined, HostRadioConnector(host, associations).connect(heard("C0:FF:EE:00:00:02"), NoPage))
        assertSame(held, host.radio.value)
        assertEquals(before, preferences.radioRegistry.bound())
        assertTrue(runtime.radio.value!!.carriesThisPhone)
        assertEquals(1, peripheral.opened.get())
    }

    /** The pairing window closed under the dialog: said as such, and nothing is bound. */
    @Test
    fun noDeviceFromTheDialogIsPairingRemoved() = runBlocking<Unit> {
        start()
        running()
        associations.answer = Association.NoDevice
        assertEquals(
            ConnectOutcome.Failed(ConnectFailure.PairingRemoved),
            HostRadioConnector(host, associations).connect(heard(), NoPage),
        )
        assertNull(preferences.radioRegistry.bound())
        assertEquals(0, peripheral.opened.get())
    }

    /** Associated already (a radio released by choosing another): no confirmation. */
    @Test
    fun anAssociatedRadioNeedsNoConfirmation() = runBlocking<Unit> {
        start()
        running()
        associations.known[address] = "5"
        assertEquals(ConnectOutcome.Connected, HostRadioConnector(host, associations).connect(heard(), NoPage))
        assertEquals(0, associations.asked.get())
        assertEquals("5", preferences.radioRegistry.bound()?.associationId)
    }

    /**
     * A first pairing that fails takes its new association with it; one the
     * radio had before stays, unless the radio refused this phone's keys,
     * which leaves nothing worth keeping.
     */
    @Test
    fun aFailedPairingReleasesOnlyANewOrRefusedAssociation() = runBlocking<Unit> {
        start()
        running()
        peripheral.refuseCccd = true
        assertEquals(
            ConnectOutcome.Failed(ConnectFailure.PairingRemoved),
            HostRadioConnector(host, associations).connect(heard(), NoPage),
        )
        assertEquals(listOf("7"), associations.released)
        assertNull(preferences.radioRegistry.bound())

        associations.known[address] = "5"
        assertEquals(
            ConnectOutcome.Failed(ConnectFailure.PairingRemoved),
            HostRadioConnector(host, associations).connect(heard(), NoPage),
        )
        assertEquals(listOf("7", "5"), associations.released)

        peripheral.refuseCccd = false
        peripheral.unreachable = 147
        associations.known[address] = "6"
        assertEquals(
            ConnectOutcome.Failed(ConnectFailure.PairingRemoved),
            HostRadioConnector(host, associations).connect(heard(), NoPage),
        )
        assertEquals(listOf("7", "5"), associations.released)
    }

    /**
     * The pairing window closed under the confirmation, and with it the
     * address: the connect times out once, and that is the end of it, said
     * as a window to open again. Nothing is left bound or associated.
     */
    @Test
    fun aPairingRadioGoneFromItsAddressIsPairingRemoved() = runBlocking<Unit> {
        start()
        running()
        peripheral.unreachable = 147
        assertEquals(
            ConnectOutcome.Failed(ConnectFailure.PairingRemoved),
            HostRadioConnector(host, associations).connect(heard(), NoPage),
        )
        assertEquals(1, peripheral.opened.get())
        assertEquals(listOf("7"), associations.released)
        assertNull(preferences.radioRegistry.bound())
    }

    /**
     * Android's generic failure on a first connect is tried once more,
     * directly; then the attempt ends as a radio that could not be reached
     * (off, or out of range), not as a pairing window to open again.
     */
    @Test
    fun aPairingConnectFailingTwiceEnds() = runBlocking<Unit> {
        start()
        running()
        peripheral.unreachable = 133
        assertEquals(
            ConnectOutcome.Failed(ConnectFailure.ConnectFailed),
            HostRadioConnector(host, associations).connect(heard(), NoPage),
        )
        assertEquals(2, peripheral.opened.get())
        delay(300)
        assertEquals(2, peripheral.opened.get())
    }

    /** A factory reset the radio took: once its link drops, its association goes too. */
    @Test
    fun aFactoryResetReleasesTheAssociation() = runBlocking<Unit> {
        start()
        val runtime = running()
        HostRadioConnector(host, associations).connect(heard(), NoPage)
        runtime.radioWhere { it.carriesThisPhone }
        val connection = host.radio.value as BleRadioConnection
        connection.linkForTests.abandonBinding()
        withTimeout(TIMEOUT) { preferences.radioRegistry.bound.first { it == null } }
        peripheral.drop()
        withTimeout(TIMEOUT) { while (associations.released.isEmpty()) delay(20) }
        assertEquals(listOf("7"), associations.released)
        withTimeout(TIMEOUT) { host.radio.first { it == null } }
    }

    /**
     * Choosing another radio closes the one held, its link included. (That
     * the close reaches the link even behind queued work is
     * [RadioDriverAdapterCloseTest]'s.)
     */
    @Test
    fun anotherRadioClosesTheHeldLink() = runBlocking<Unit> {
        start()
        val runtime = connect()
        runtime.radioWhere { it.carriesThisPhone }
        val first = peripheral.ports.single()
        val other = "C0:FF:EE:00:00:02"
        host.connectRadio(BoundRadio(RadioKind.Ble, other, modelId = 2, name = "T1000-E 9B10")).bound.join()
        withTimeout(TIMEOUT) { while (!first.closed) delay(20) }
        // The new radio comes up on its own port, which the old one's close never touches.
        runtime.radioWhere { it.carriesThisPhone && it.linkId == other }
        assertTrue(peripheral.ports.size >= 2)
        assertFalse(peripheral.ports.last().closed)
    }

    /**
     * Choose a radio with radio A held: B is allowed, A released, and B
     * never comes up. A keeps its association, so Choose a radio still
     * offers it and choosing it again needs no confirmation (§2.2); only
     * B's new association goes. Then A is chosen again and attaches.
     */
    @Test
    fun aFailedChoiceLeavesTheReleasedRadioAssociated() = runBlocking<Unit> {
        start()
        val runtime = running()
        val other = "C0:FF:EE:00:00:02"
        associations.known[address] = "5"
        assertEquals(ConnectOutcome.Connected, HostRadioConnector(host, associations).connect(heard(), NoPage))
        runtime.radioWhere { it.carriesThisPhone && it.linkId == address }

        peripheral.unreachable = 133
        associations.answer = Association.Made("7", other)
        assertEquals(
            ConnectOutcome.Failed(ConnectFailure.ConnectFailed),
            HostRadioConnector(host, associations).connect(heard(other), NoPage),
        )
        assertEquals(listOf("7"), associations.released)
        assertEquals("5", associations.associationFor(address))
        assertNull(preferences.radioRegistry.bound())

        peripheral.unreachable = null
        assertEquals(ConnectOutcome.Connected, HostRadioConnector(host, associations).connect(heard(), NoPage))
        assertEquals(1, associations.asked.get())
        assertEquals("5", preferences.radioRegistry.bound()?.associationId)
    }

    /**
     * An attempt called off late (its page left while the radio paired)
     * never forgets the radio a later attempt chose since, even the same
     * one: the later choice holds it.
     */
    @Test
    fun aSupersededAttemptLeavesTheLaterChoice() = runBlocking<Unit> {
        start()
        val runtime = running()
        peripheral.holdBond = true
        val first = scope.launch { HostRadioConnector(host, associations).connect(heard(), NoPage) }
        runtime.radioWhere { it.phase == MobileRadioPhase.PAIRING }
        // The same radio chosen again (now associated) before the first
        // attempt's cleanup has run.
        associations.known[address] = "7"
        val later = host.connectRadio(BoundRadio(RadioKind.Ble, address, associationId = "7", modelId = 2))
        first.cancel()
        first.join()
        later.bound.join()
        assertEquals(address, preferences.radioRegistry.bound()?.linkId)
        assertTrue(associations.released.isEmpty())
        assertEquals(address, host.radio.value?.linkId)
    }

    /** A bind that never took (no link for the radio) still takes its new association with it. */
    @Test
    fun aBindThatNeverTookReleasesItsAssociation() = runBlocking<Unit> {
        start()
        running()
        noLinkFor = address
        val outcome = HostRadioConnector(host, associations).connect(heard(), NoPage)
        assertTrue(outcome is ConnectOutcome.Failed)
        assertEquals(listOf("7"), associations.released)
        assertNull(preferences.radioRegistry.bound())
    }

    // endregion

    /** Bluetooth off rests the link as Unavailable; back on, it reconnects. */
    @Test
    fun bluetoothOffIsUnavailable() = runBlocking<Unit> {
        start()
        val runtime = connect()
        runtime.radioWhere { it.carriesThisPhone }
        bluetooth.value = BluetoothStatus(BluetoothStatus.Adapter.Off, nearbyGranted = true)
        runtime.radioWhere { it.phase == MobileRadioPhase.UNAVAILABLE }
        bluetooth.value = BluetoothStatus.Ready
        runtime.radioWhere { it.carriesThisPhone }
    }

    // region The reconnect window and the strategies (§7.2)

    /** The radio drops and returns within the window: Reconnecting, with a background connect, then attached. */
    @Test
    fun aRadioBackWithinTheWindowIsReconnecting() = runBlocking<Unit> {
        start()
        val runtime = connect()
        runtime.radioWhere { it.carriesThisPhone }
        peripheral.away = true
        peripheral.drop()
        runtime.radioWhere { it.phase == MobileRadioPhase.RECONNECTING }
        withTimeout(TIMEOUT) { while (!peripheral.sought) delay(20) }
        // Still Reconnecting while the background connect waits.
        assertEquals(MobileRadioPhase.RECONNECTING, runtime.radio.value?.phase)
        peripheral.comeBack()
        runtime.radioWhere { it.carriesThisPhone }
    }

    /**
     * The name the radio reports for itself is the one it goes by, attached
     * or not: the registry keeps it, and the transport says it while the
     * link is away, rather than the name it was set up under (DP-80).
     */
    @Test
    fun theReportedNameOutlastsTheLink() = runBlocking<Unit> {
        start()
        val runtime = connect()
        val reported = runtime.radioWhere { it.carriesThisPhone && it.name != null && it.name != "T1000-E 4F2A" }.name
        withTimeout(TIMEOUT) { preferences.radioRegistry.bound.first { it?.name == reported } }
        peripheral.away = true
        peripheral.drop()
        assertEquals(reported, runtime.radioWhere { it.phase == MobileRadioPhase.RECONNECTING }.name)
        // A new process starts from the registry's name: the same one.
        val next = newProcess()
        assertEquals(reported, next.radioWhere { it.name != null }.name)
    }

    /**
     * Presence strategy: past the window the link closes and the radio is
     * Waiting, with nothing sought; presence's wake seeks it again.
     */
    @Test
    fun pastTheWindowPresenceClosesTheLinkUntilAWake() = runBlocking<Unit> {
        strategy.value = ReconnectStrategy.Presence
        windowMs = 600
        start()
        val runtime = connect()
        runtime.radioWhere { it.carriesThisPhone }
        peripheral.away = true
        peripheral.drop()
        runtime.radioWhere { it.phase == MobileRadioPhase.RECONNECTING }
        runtime.radioWhere { it.phase == MobileRadioPhase.WAITING_FOR_RADIO }
        assertFalse(peripheral.sought)
        val opened = peripheral.opened.get()
        delay(400)
        assertEquals(opened, peripheral.opened.get())
        // Presence saw it: the wake seeks it with a new window, and it attaches.
        peripheral.away = false
        host.wakeRadio().join()
        runtime.radioWhere { it.carriesThisPhone }
    }

    /** Waiting strategy: past the window the background connect stays armed, and the radio attaches when it is back. */
    @Test
    fun pastTheWindowWaitingKeepsAConnectArmed() = runBlocking<Unit> {
        strategy.value = ReconnectStrategy.Waiting
        windowMs = 600
        start()
        val runtime = connect()
        runtime.radioWhere { it.carriesThisPhone }
        peripheral.away = true
        peripheral.drop()
        runtime.radioWhere { it.phase == MobileRadioPhase.WAITING_FOR_RADIO }
        withTimeout(TIMEOUT) { while (!peripheral.sought) delay(20) }
        // A wake while it waits changes nothing: it is already sought.
        val opened = peripheral.opened.get()
        host.wakeRadio().join()
        delay(200)
        assertEquals(opened, peripheral.opened.get())
        peripheral.comeBack()
        runtime.radioWhere { it.carriesThisPhone }
    }

    /** Bluetooth off for longer than the window: Unavailable throughout, never Waiting; back on, the radio is sought at once. */
    @Test
    fun bluetoothOffOutlastingTheWindowStaysUnavailable() = runBlocking<Unit> {
        strategy.value = ReconnectStrategy.Presence
        windowMs = 400
        start()
        val runtime = connect()
        runtime.radioWhere { it.carriesThisPhone }
        bluetooth.value = BluetoothStatus(BluetoothStatus.Adapter.Off, nearbyGranted = true)
        runtime.radioWhere { it.phase == MobileRadioPhase.UNAVAILABLE }
        delay(800)
        assertEquals(MobileRadioPhase.UNAVAILABLE, runtime.radio.value?.phase)
        bluetooth.value = BluetoothStatus.Ready
        runtime.radioWhere { it.carriesThisPhone }
    }

    /** A wake never brings back a radio the driver gave up on: only the user's Reconnect does. */
    @Test
    fun aWakeLeavesARadioTheDriverGaveUpOn() = runBlocking<Unit> {
        start()
        peripheral.refuseCccd = true
        val runtime = connect()
        runtime.radioWhere { it.phase == MobileRadioPhase.FAILED }
        val tries = peripheral.opened.get()
        host.wakeRadio().join()
        delay(400)
        assertEquals(tries, peripheral.opened.get())
        assertEquals(MobileRadioPhase.FAILED, runtime.radio.value?.phase)
        // The give-up is kept: presence stops observing it.
        val bound = withTimeout(TIMEOUT) { preferences.radioRegistry.bound.first { it?.autoConnect == false } }
        assertNull(RadioPresence.observedFor(bound?.copy(associationId = "7"), ReconnectStrategy.Presence, available = true))
        // The user's Reconnect does.
        peripheral.refuseCccd = false
        host.reconnectRadio().join()
        runtime.radioWhere { it.carriesThisPhone }
        assertEquals(true, preferences.radioRegistry.bound()?.autoConnect)
    }

    /** A give-up outlives the process: the next one, and a wake in it, seek nothing (§7.2). */
    @Test
    fun aRadioTheDriverGaveUpOnStaysDownInANewProcess() = runBlocking<Unit> {
        start()
        peripheral.refuseCccd = true
        val runtime = connect()
        runtime.radioWhere { it.phase == MobileRadioPhase.FAILED }
        withTimeout(TIMEOUT) { preferences.radioRegistry.bound.first { it?.autoConnect == false } }
        val tries = peripheral.opened.get()
        val next = newProcess()
        host.wakeRadio().join()
        delay(400)
        assertEquals(tries, peripheral.opened.get())
        assertTrue(next.radio.value?.phase != MobileRadioPhase.CONNECTING)
    }

    /** The phone slept through the window's end: the first check awake closes it, by the clock that counts sleep. */
    @Test
    fun aWindowThatEndsInSleepClosesOnWaking() = runBlocking<Unit> {
        strategy.value = ReconnectStrategy.Presence
        windowMs = 60_000
        windowRecheckMs = 200
        start()
        val runtime = connect()
        runtime.radioWhere { it.carriesThisPhone }
        peripheral.away = true
        peripheral.drop()
        runtime.radioWhere { it.phase == MobileRadioPhase.RECONNECTING }
        slept.addAndGet(windowMs)
        runtime.radioWhere { it.phase == MobileRadioPhase.WAITING_FOR_RADIO }
        assertFalse(peripheral.sought)
    }

    /** The Developer switch to Waiting with the radio left to presence: a background connect is armed at once. */
    @Test
    fun switchingToWaitingPastTheWindowArmsAConnect() = runBlocking<Unit> {
        strategy.value = ReconnectStrategy.Presence
        windowMs = 600
        start()
        val runtime = connect()
        runtime.radioWhere { it.carriesThisPhone }
        peripheral.away = true
        peripheral.drop()
        runtime.radioWhere { it.phase == MobileRadioPhase.WAITING_FOR_RADIO }
        assertFalse(peripheral.sought)
        strategy.value = ReconnectStrategy.Waiting
        withTimeout(TIMEOUT) { while (!peripheral.sought) delay(20) }
        assertEquals(MobileRadioPhase.WAITING_FOR_RADIO, runtime.radio.value?.phase)
        peripheral.comeBack()
        runtime.radioWhere { it.carriesThisPhone }
    }

    /** The Developer switch to Presence while waiting: the background connect is closed. */
    @Test
    fun switchingToPresencePastTheWindowClosesTheLink() = runBlocking<Unit> {
        strategy.value = ReconnectStrategy.Waiting
        windowMs = 600
        start()
        val runtime = connect()
        runtime.radioWhere { it.carriesThisPhone }
        peripheral.away = true
        peripheral.drop()
        runtime.radioWhere { it.phase == MobileRadioPhase.WAITING_FOR_RADIO }
        withTimeout(TIMEOUT) { while (!peripheral.sought) delay(20) }
        strategy.value = ReconnectStrategy.Presence
        withTimeout(TIMEOUT) { while (peripheral.sought) delay(20) }
        val opened = peripheral.opened.get()
        delay(400)
        assertEquals(opened, peripheral.opened.get())
        assertEquals(MobileRadioPhase.WAITING_FOR_RADIO, runtime.radio.value?.phase)
    }

    /** Disconnect ends the standing intent: a wake seeks nothing. */
    @Test
    fun aWakeLeavesADisconnectedRadio() = runBlocking<Unit> {
        start()
        val runtime = connect()
        runtime.radioWhere { it.carriesThisPhone }
        host.disconnectRadio().join()
        runtime.radioWhere { it.phase == MobileRadioPhase.IDLE }
        val opened = peripheral.opened.get()
        host.wakeRadio().join()
        delay(300)
        assertEquals(opened, peripheral.opened.get())
        assertEquals(false, preferences.radioRegistry.bound()?.autoConnect)
    }

    /** DFU: the link goes down and stays down, the binding is kept, and presence stops observing it. */
    @Test
    fun dfuStopsReconnectingAndKeepsTheBinding() = runBlocking<Unit> {
        start()
        val runtime = running()
        HostRadioConnector(host, associations).connect(heard(), NoPage)
        runtime.radioWhere { it.carriesThisPhone }
        val connection = host.radio.value as BleRadioConnection
        connection.linkForTests.didEnterDfu()
        runtime.radioWhere { it.phase == MobileRadioPhase.IDLE }
        val bound = withTimeout(TIMEOUT) { preferences.radioRegistry.bound.first { it?.autoConnect == false } }
        assertEquals("7", bound?.associationId)
        assertTrue(associations.released.isEmpty())
        assertNull(RadioPresence.observedFor(bound, ReconnectStrategy.Presence, available = true))
        val opened = peripheral.opened.get()
        host.wakeRadio().join()
        delay(300)
        assertEquals(opened, peripheral.opened.get())
    }

    /** A factory reset: the registry is cleared, so presence observes nothing. */
    @Test
    fun aFactoryResetStopsPresence() = runBlocking<Unit> {
        start()
        val runtime = running()
        HostRadioConnector(host, associations).connect(heard(), NoPage)
        runtime.radioWhere { it.carriesThisPhone }
        assertEquals("7", RadioPresence.observedFor(preferences.radioRegistry.bound(), ReconnectStrategy.Presence, available = true))
        (host.radio.value as BleRadioConnection).linkForTests.abandonBinding()
        val bound = withTimeout(TIMEOUT) { preferences.radioRegistry.bound.first { it == null } }
        assertNull(RadioPresence.observedFor(bound, ReconnectStrategy.Presence, available = true))
    }

    // endregion

    private companion object {
        const val TIMEOUT = 30_000L
        const val CMD_STR_SEND: Byte = 9

        /** A `BluetoothDevice` the JVM can hold: the connector only hands it on. */
        @Suppress("UNCHECKED_CAST")
        fun <T> unconstructed(type: Class<T>): T {
            val field = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe").apply { isAccessible = true }
            val unsafe = field.get(null)
            return unsafe.javaClass.getMethod("allocateInstance", Class::class.java).invoke(unsafe, type) as T
        }

        inline fun <reified T> unconstructed(): T = unconstructed(T::class.java)
    }
}
