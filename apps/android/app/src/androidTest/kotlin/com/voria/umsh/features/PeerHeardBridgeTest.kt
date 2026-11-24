package com.voria.umsh.features

import android.Manifest
import android.app.NotificationManager
import android.content.Intent
import android.os.Build
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.MainActivity
import com.voria.umsh.app.Tags
import com.voria.umsh.services.notifications.NoticeKind
import com.voria.umsh.services.preferences.OnboardingStep
import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.RadioKind
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test

/**
 * Next time heard end to end, over `make android-bridge` (gated: `-e
 * bridge <address>` names `umshctl`'s own node on the bridge's "peer"
 * host). The live core reaches the bridge's "phone" host; once this logs
 * `ARMED phone=<address>`, the run sends to that address from the peer
 * host (`umshctl --tcp 127.0.0.1:21839 send <address> <text>`); the notice that
 * fires is tapped, and the app opens at the node.
 */
class PeerHeardBridgeTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createEmptyComposeRule()

    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val peer: String? get() = InstrumentationRegistry.getArguments().getString("bridge")

    @Test
    fun anAdvertFiresTheNoticeAndItsTapOpensTheNode() {
        val address = peer
        assumeTrue("needs -e bridge <address>", address != null)
        address!!
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
        }
        runBlocking {
            fresh.host.preferences.setNotificationsAsked()
            fresh.host.preferences.radioRegistry.bind(BoundRadio(RadioKind.Tcp, BRIDGE))
        }
        val scenario = ActivityScenario.launch<MainActivity>(Intent(context, MainActivity::class.java))
        val runtime = runBlocking {
            val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
            ready.runtime.setOnboarding(OnboardingStep.Done).await()
            withTimeout(TIMEOUT) { ready.runtime.radio.first { it?.carriesThisPhone == true } }
            ready.runtime
        }
        val manager = context.getSystemService(NotificationManager::class.java)
        // An earlier run's notice for the same node would otherwise pass for this one's.
        manager.cancelAll()
        val armedAt = System.currentTimeMillis()
        // Saved by its address with a conversation, as Add peer by key does, so the radio
        // carries its key (unicast from a node it has no key for never reaches the phone); then armed.
        runBlocking {
            runtime.core.savePeer(address, null, true)
            runtime.reload(full = true).await()
            runtime.setNotifyWhenHeard(address, true).await()
        }
        // The run reads this line, then sends from the peer host.
        android.util.Log.i(TAG, "ARMED phone=${runtime.identity.value.address}")
        fun heard() = manager.activeNotifications.firstOrNull { it.tag == address && it.id == NoticeKind.Heard.id && it.postTime >= armedAt }
        compose.waitUntil(HEARD_TIMEOUT) { heard() != null }
        android.util.Log.i(TAG, "notice posted")
        val notice = heard()!!
        android.util.Log.i(TAG, "still armed: ${runtime.appState.value?.peers?.firstOrNull { it.address == address }?.notifyWhenHeard}")
        notice.notification.contentIntent.send()
        val offersText = runtime.appState.value!!.peers.first { it.address == address }.offersTextMessages
        val opened = if (offersText) Tags.THREAD else Tags.PEER_PAGE
        compose.waitUntil(TIMEOUT) { compose.onAllNodesWithTag(opened).fetchSemanticsNodes().isNotEmpty() }
        android.util.Log.i(TAG, "tap opened $opened")
        // The tap reached this activity by onNewIntent (CLEAR_TOP | SINGLE_TOP), after which
        // ActivityScenario's close waits for a destruction it no longer sees: finished directly.
        scenario.onActivity { it.finish() }
    }

    private companion object {
        const val TAG = "PeerHeardBridgeTest"
        const val BRIDGE = "10.0.2.2:21838"
        const val TIMEOUT = 30_000L
        const val HEARD_TIMEOUT = 180_000L
    }
}
