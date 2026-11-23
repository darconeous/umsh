package com.voria.umsh.services.radio

import android.bluetooth.BluetoothDevice
import android.content.IntentSender
import androidx.activity.result.ActivityResult
import com.voria.umsh.features.onboarding.ConnectFailure
import com.voria.umsh.features.onboarding.FoundRadio
import com.voria.umsh.features.onboarding.RadioScanState
import com.voria.umsh.features.onboarding.ScanRequest
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** Connect a radio's search over a scripted scanner and connector (§3.3), on a virtual clock. */
@OptIn(ExperimentalCoroutinesApi::class)
class BleScanSourceTest {
    private class Scanner : RadioScanner {
        var starts = 0
        var stops = 0
        var running = false
        var refuse = false
        var heard: ((HeardRadio) -> Unit)? = null
        var failed: ((Int) -> Unit)? = null

        override fun start(onHeard: (HeardRadio) -> Unit, onFailed: (Int) -> Unit): Boolean {
            starts += 1
            if (refuse) return false
            running = true
            heard = onHeard
            failed = onFailed
            return true
        }

        override fun stop() {
            stops += 1
            running = false
        }
    }

    private val dispatcher = StandardTestDispatcher()
    private val scanner = Scanner()
    private val attempt = CompletableDeferred<ConnectOutcome>()

    /** What the connector's confirmation came back with, when a test has it ask. */
    private var confirmedWith: ActivityResult? = null
    private var asksConfirmation = false
    private lateinit var source: BleRadioScanSource

    private val pairing = RadioAdvertisement(discoverable = true, modelId = 2, name = "T1000-E 4F2A", hasService = true)

    @Before
    fun setUp() {
        Dispatchers.setMain(dispatcher)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
    }

    /** The addresses the phone has associated, as Choose a radio reads them. */
    private var associated: Set<String> = emptySet()

    private fun TestScope.started(): BleRadioScanSource {
        source = BleRadioScanSource(
            MutableStateFlow(BluetoothStatus.Ready),
            scanner,
            { _, page ->
                if (asksConfirmation) confirmedWith = page.confirm(sender)
                attempt.await()
            },
            clock = { testScheduler.currentTime },
            associated = { associated },
        )
        source.start()
        runCurrent()
        return source
    }

    private fun TestScope.hear(address: String) {
        scanner.heard!!(HeardRadio(device, address, pairing))
        runCurrent()
    }

    /** A test on the virtual clock; the source stops however it ends, or its prune loop would run on forever. */
    private fun scan(body: suspend TestScope.() -> Unit) = runTest(dispatcher) {
        try {
            body()
        } finally {
            source.stop()
        }
    }

    private val looking: RadioScanState.Looking get() = source.state.value as RadioScanState.Looking

    /**
     * Choose a radio: a radio this phone has associated (one released by
     * choosing another that then failed) is listed out of its pairing
     * window, and tapping it connects; one not associated is not (§2.2,
     * D16). Associations are read again after an attempt.
     */
    @Test
    fun anAssociatedRadioIsListedOutOfItsWindow() = scan {
        val bonded = RadioAdvertisement(discoverable = false, modelId = null, name = "T1000-E 4F2A", hasService = true)
        associated = setOf("C0:FF:EE:00:00:01")
        started()
        scanner.heard!!(HeardRadio(device, "c0:ff:ee:00:00:01", bonded))
        scanner.heard!!(HeardRadio(device, "C0:FF:EE:00:00:02", bonded))
        runCurrent()
        assertEquals(listOf("c0:ff:ee:00:00:01"), looking.radios.map { it.id })
        source.connect(looking.radios.single())
        runCurrent()
        assertEquals("c0:ff:ee:00:00:01", looking.connecting)

        associated = setOf("C0:FF:EE:00:00:02")
        attempt.complete(ConnectOutcome.Failed(ConnectFailure.ConnectFailed))
        runCurrent()
        scanner.heard!!(HeardRadio(device, "C0:FF:EE:00:00:02", bonded))
        runCurrent()
        assertEquals(listOf("c0:ff:ee:00:00:01", "C0:FF:EE:00:00:02"), looking.radios.map { it.id })
    }

    /** Out of its pairing window a radio is listed only when associated, and only with the service (D16). */
    @Test
    fun onlyAnAssociatedRadioIsListedOutOfItsWindow() {
        val list = PairingRadioList()
        val bonded = RadioAdvertisement(discoverable = false, modelId = null, name = "T1000-E 4F2A", hasService = true)
        assertEquals(false, list.heard("A", bonded, 0))
        assertEquals(true, list.heard("A", bonded, 0, associated = true))
        val noService = bonded.copy(hasService = false)
        assertEquals(false, list.heard("B", noService, 0, associated = true))
    }

    /**
     * The scan pauses while a radio connects, and the row being connected
     * stays however long the pairing takes; after a failure the scan
     * resumes, and the row stays to be tapped again.
     */
    @Test
    fun theConnectingRowOutlastsItsSilence() = scan {
        started()
        hear("A")
        source.connect(FoundRadio("A", "T1000-E 4F2A", 2))
        runCurrent()
        assertEquals(false, scanner.running)
        advanceTimeBy(60_000)
        assertEquals(listOf("A"), looking.radios.map { it.id })
        assertEquals("A", looking.connecting)
        assertEquals(1, scanner.starts)

        attempt.complete(ConnectOutcome.Failed(ConnectFailure.PairingRemoved))
        runCurrent()
        assertTrue(scanner.running)
        assertEquals(2, scanner.starts)
        assertEquals(listOf("A"), looking.radios.map { it.id })
        assertEquals(ConnectFailure.PairingRemoved, looking.failure)
        // Not heard again (it may have taken a new address): it goes soon.
        advanceTimeBy(PairingRadioList.RESUME_GRACE_MS + 1_500)
        assertTrue(looking.radios.isEmpty())
    }

    /**
     * Android's confirmation goes to the page as a request, and the page's
     * answer back to the connector; declining it says nothing, and the
     * search carries on.
     */
    @Test
    fun aConfirmationGoesThroughThePageAndADeclineSaysNothing() = scan {
        asksConfirmation = true
        started()
        val requests = mutableListOf<ScanRequest>()
        val collecting = backgroundScope.launch { source.requests.collect { requests += it } }
        hear("A")
        source.connect(FoundRadio("A", "T1000-E 4F2A", 2))
        runCurrent()
        assertSame(sender, (requests.single() as ScanRequest.ConfirmRadio).sender)
        val answer = ActivityResult(0, null)
        source.confirmed(answer)
        runCurrent()
        assertSame(answer, confirmedWith)

        attempt.complete(ConnectOutcome.Declined)
        runCurrent()
        assertNull(looking.failure)
        assertNull(looking.connecting)
        assertTrue(scanner.running)
        collecting.cancel()
    }

    /** A search opened again after its radio connected is looking again, not finished (Choose a radio reopened). */
    @Test
    fun aSearchOpenedAgainAfterConnectingLooksAgain() = scan {
        started()
        hear("A")
        source.connect(FoundRadio("A", "T1000-E 4F2A", 2))
        attempt.complete(ConnectOutcome.Connected)
        runCurrent()
        assertEquals(RadioScanState.Connected, source.state.value)
        source.stop()
        source.start()
        runCurrent()
        assertTrue(looking.radios.isEmpty())
        assertTrue(scanner.running)
    }

    /** A scan Android fails is started again after a backoff, and again later if it fails again. */
    @Test
    fun aFailedScanStartsAgain() = scan {
        started()
        scanner.failed!!(2)
        runCurrent()
        advanceTimeBy(4_999)
        assertEquals(1, scanner.starts)
        advanceTimeBy(2)
        assertEquals(2, scanner.starts)
        scanner.failed!!(2)
        runCurrent()
        advanceTimeBy(29_999)
        assertEquals(2, scanner.starts)
        advanceTimeBy(2)
        assertEquals(3, scanner.starts)
    }

    /** One Android would not start at all is tried again too. */
    @Test
    fun anUnstartableScanIsTriedAgain() = scan {
        scanner.refuse = true
        started()
        assertEquals(1, scanner.starts)
        scanner.refuse = false
        advanceTimeBy(5_001)
        assertEquals(2, scanner.starts)
        assertTrue(scanner.running)
    }

    private companion object {
        /** A `BluetoothDevice` the JVM can hold: the source only hands it on. */
        val device: BluetoothDevice = unconstructed()

        /** Likewise an `IntentSender`: the page would launch it. */
        val sender: IntentSender = unconstructed()

        inline fun <reified T> unconstructed(): T {
            val field = Class.forName("sun.misc.Unsafe").getDeclaredField("theUnsafe").apply { isAccessible = true }
            val unsafe = field.get(null)
            return unsafe.javaClass.getMethod("allocateInstance", Class::class.java).invoke(unsafe, T::class.java) as T
        }
    }
}
