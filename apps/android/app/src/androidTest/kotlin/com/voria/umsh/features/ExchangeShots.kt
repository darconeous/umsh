package com.voria.umsh.features

import android.graphics.Bitmap
import android.view.inputmethod.InputMethodManager
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.compose.ui.unit.dp
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.app.AppRoot
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.UmshTheme
import com.voria.umsh.features.peers.LocalExchangeHost
import com.voria.umsh.features.peers.MeetGlyph
import com.voria.umsh.features.peers.MeetGlyphKind
import com.voria.umsh.features.peers.MeetNearness
import com.voria.umsh.features.peers.meetModelName
import com.voria.umsh.models.MeetEnd
import com.voria.umsh.models.MeetExchange
import com.voria.umsh.services.preferences.OnboardingStep
import java.io.File
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * Screenshots of `nearby-exchange.svg` 1–7, and `add-peer.svg` 1–2 now that
 * Add peer has Nearby, for the build report: the real app root over the
 * staged core, its exchange held in each board's state by hand
 * ([FakeExchangeHost]) with the board's four devices and its code. Off
 * unless the run passes `-e shots <suffix>`; they land in the app's
 * external files, under `shots/`.
 */
class ExchangeShots {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private val suffix: String? get() = InstrumentationRegistry.getArguments().getString("shots")

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private val exchange = FakeExchangeHost()

    @Before
    fun onlyWhenAsked() = assumeTrue(suffix != null)

    private fun shot(name: String) {
        compose.waitForIdle()
        Thread.sleep(SETTLE_MS)
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val bitmap = instrumentation.uiAutomation.takeScreenshot() ?: return
        val directory = File(instrumentation.targetContext.getExternalFilesDir(null), "shots").apply { mkdirs() }
        File(directory, "$name-$suffix.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    private fun start(): AppRuntime {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            InstrumentationRegistry.getInstrumentation().uiAutomation.grantRuntimePermission(context.packageName, android.Manifest.permission.POST_NOTIFICATIONS)
        }
        runBlocking {
            fresh.host.preferences.setFallbackScheme(true)
            fresh.host.preferences.setNotificationsAsked()
        }
        fresh.host.ensureRuntime(staging = true)
        val runtime = runBlocking {
            val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
            ready.runtime.setOnboarding(OnboardingStep.Done).await()
            withTimeout(TIMEOUT) { ready.runtime.radio.first { it?.carriesThisPhone == true } }
            withTimeout(TIMEOUT) { ready.runtime.appState.first { state -> state != null && state.peers.any { !it.isSaved && !it.isCompanionRadio } } }
            ready.runtime
        }
        compose.setContent { CompositionLocalProvider(LocalExchangeHost provides exchange) { AppRoot(fresh.host) } }
        return runtime
    }

    private fun present(tag: String) = compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()

    private fun waitFor(tag: String) = compose.waitUntil(TIMEOUT) { present(tag) }

    private fun hideKeyboard() = compose.runOnUiThread {
        val view = compose.activity.window.decorView
        view.context.getSystemService(InputMethodManager::class.java).hideSoftInputFromWindow(view.windowToken, 0)
    }

    private fun openAddPeer() {
        waitFor(Tags.NAV_PEERS)
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitFor(Tags.PEERS_ADD)
        compose.onNodeWithTag(Tags.PEERS_ADD).performClick()
        waitFor(Tags.ADD_PEER)
    }

    /** Boards 1–6, and Add peer's own boards 1–2 with Nearby. */
    @Test
    fun exchange() {
        val runtime = start()
        exchange.meet.value = FakeExchangeHost.open()
        openAddPeer()
        compose.waitUntil(TIMEOUT) { compose.onAllNodesWithTag(Tags.NEARBY_DEVICE).fetchSemanticsNodes().size == 4 }
        shot("add-peer-1")

        exchange.move(MeetExchange.Asked(FakeExchangeHost.pager), FakeExchangeHost.pager)
        waitFor(Tags.EXCHANGE_ACCEPT)
        shot("nearby-exchange-1")

        exchange.move(MeetExchange.Asking(FakeExchangeHost.pager))
        waitFor(Tags.EXCHANGE_WAITING)
        compose.waitUntil(TIMEOUT) { !present(Tags.EXCHANGE_ASKED) }
        shot("nearby-exchange-2")

        exchange.move(MeetExchange.Comparing(FakeExchangeHost.pager, 123_456, sent = false))
        waitFor(Tags.EXCHANGE_SAME)
        shot("nearby-exchange-3")

        exchange.move(MeetExchange.Comparing(FakeExchangeHost.pager, 123_456, sent = true))
        waitFor(Tags.EXCHANGE_SAME_PRESSED)
        shot("nearby-exchange-4")

        exchange.move(MeetExchange.Ended(MeetEnd.Different))
        waitFor(Tags.EXCHANGE_ENDED)
        shot("nearby-exchange-5")
        exchange.move(MeetExchange.Ended(MeetEnd.Left))
        shot("nearby-exchange-5-not-exchanged")

        // Board 6: an unsaved node, as an exchanged one is, on its own page in Add peer's place.
        val unsaved = runtime.appState.value!!.peers.first { !it.isSaved && !it.isCompanionRadio }
        exchange.move(MeetExchange.Exchanged(unsaved.address, signed = true))
        waitFor(Tags.PEER_PAGE)
        shot("nearby-exchange-6")

        // Add peer board 2: no radio for this phone, and a bad link.
        exchange.meet.value = null
        compose.onNodeWithTag(Tags.TOP_BAR_BACK).performClick()
        waitFor(Tags.PEERS_ADD)
        compose.onNodeWithTag(Tags.PEERS_ADD).performClick()
        waitFor(Tags.ADD_PEER)
        exchange.carries.value = false
        waitFor(Tags.NEARBY_NO_RADIO)
        compose.onNodeWithTag(Tags.ADD_PEER_FIELD).performTextReplacement("umsh:x:Mx4eTq8VbN3k")
        compose.onNodeWithTag(Tags.ADD_PEER_PREVIEW).performScrollTo().performClick()
        hideKeyboard()
        waitFor(Tags.ADD_PEER_PROBLEM)
        shot("add-peer-2")
    }

    /** Board 7: each kind of device, nearness 0–3, and colors as sessions draw them. */
    @Test
    fun glyphs() {
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                Surface(Modifier.fillMaxSize()) {
                    Column(Modifier.safeDrawingPadding().padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                        listOf(
                            MeetGlyphKind.Phone to FakeExchangeHost.ANDROID_PHONE,
                            MeetGlyphKind.Tablet to 0xFE03,
                            MeetGlyphKind.Computer to 0xFE05,
                            MeetGlyphKind.Board to FakeExchangeHost.PAGER,
                        ).forEachIndexed { index, (kind, model) ->
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                                MeetGlyph(COLORS[index + 1], kind)
                                Text(meetModelName(model), style = MaterialTheme.typography.bodyLarge)
                            }
                        }
                        Row(horizontalArrangement = Arrangement.spacedBy(32.dp)) { for (nearness in 0..3) MeetNearness(nearness) }
                        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) { for (color in COLORS) MeetGlyph(color, MeetGlyphKind.Phone, diameter = 32.dp) }
                    }
                }
            }
        }
        shot("nearby-exchange-7")
    }

    private companion object {
        const val TIMEOUT = 30_000L
        const val SETTLE_MS = 800L

        /** As the board draws session colors. */
        val COLORS = listOf(0xEC8FA8, 0xC9A84A, 0x3CC6B4, 0x8EA6F5, 0xB39AF0)
    }
}
