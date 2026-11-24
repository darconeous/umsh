package com.voria.umsh.features

import android.Manifest
import android.content.ClipboardManager
import android.content.Intent
import android.os.Build
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.MainActivity
import com.voria.umsh.app.SendOutcome
import com.voria.umsh.app.Tags
import com.voria.umsh.models.DirectConversationSummary
import com.voria.umsh.services.preferences.OnboardingStep
import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.RadioKind
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test

/**
 * Two phones over `make android-bridge ANDROID_BRIDGE_LAN=` (gated: `-e
 * addPeerBridge host|guest`). The host (api36, the bridge's "peer" host on
 * 21839) copies its own link from Your identity's QR sheet and logs
 * `READY link=<link>`. The guest (api31, "phone" on 21838, `-e link
 * <link>`) pastes that link into Add peer, saves it, and logs its own link
 * (`GUEST link=<link>`). A unicast names its sender only by hint, so the
 * receiver must hold the sender's key too: the run writes the guest's link
 * into the host's files (`peer-link.txt`), the host saves it (the other
 * half of swapping codes) and logs `SAVED_GUEST`, and the run writes
 * `go.txt` into the guest's files. The guest then messages the host from
 * its page, and the host answers the first message it is sent.
 */
class AddPeerBridgeTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createEmptyComposeRule()

    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val role: String? get() = InstrumentationRegistry.getArguments().getString("addPeerBridge")

    private fun present(tag: String) = compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()

    private fun waitForTag(tag: String) = compose.waitUntil(TIMEOUT) { present(tag) }

    private fun launch(port: Int): AppRuntime {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
        }
        runBlocking {
            fresh.host.preferences.setNotificationsAsked()
            fresh.host.preferences.radioRegistry.bind(BoundRadio(RadioKind.Tcp, "10.0.2.2:$port"))
        }
        ActivityScenario.launch<MainActivity>(Intent(context, MainActivity::class.java))
        return runBlocking {
            val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
            ready.runtime.setOnboarding(OnboardingStep.Done).await()
            withTimeout(TIMEOUT) { ready.runtime.radio.first { it?.carriesThisPhone == true } }
            ready.runtime
        }
    }

    @Test
    fun host() {
        assumeTrue("needs -e addPeerBridge host", role == "host")
        val runtime = launch(PEER_PORT)
        waitForTag(Tags.NAV_SETTINGS)
        compose.onAllNodesWithTag(Tags.NAV_SETTINGS)[0].performClick()
        waitForTag(Tags.SETTINGS_YOUR_IDENTITY)
        compose.onNodeWithTag(Tags.SETTINGS_YOUR_IDENTITY).performClick()
        waitForTag(Tags.IDENTITY_QR)
        compose.onNodeWithTag(Tags.IDENTITY_QR).performClick()
        compose.waitUntil(TIMEOUT) {
            compose.onAllNodesWithTag(Tags.QR_COPY_LINK).fetchSemanticsNodes()
                .any { SemanticsActions.OnClick in it.config && SemanticsProperties.Disabled !in it.config }
        }
        compose.onNodeWithTag(Tags.QR_COPY_LINK).performScrollTo().performClick()
        compose.waitForIdle()
        var link: String? = null
        instrumentation.runOnMainSync {
            link = context.getSystemService(ClipboardManager::class.java).primaryClip?.getItemAt(0)?.text?.toString()
        }
        android.util.Log.i(TAG, "READY link=$link")
        assumeTrue("the link was copied", link?.startsWith("umsh:") == true)
        val guestLink = runBlocking { awaitFile("peer-link.txt") }
        runBlocking { runtime.savePeer(guestLink, null, startConversation = false).await() }
        android.util.Log.i(TAG, "SAVED_GUEST")

        val conversation = runBlocking {
            withTimeout(HEARD_TIMEOUT) {
                var found: DirectConversationSummary? = null
                var polls = 0
                while (found == null) {
                    val state = runtime.appState.value
                    found = state?.directConversations?.firstOrNull { conversation ->
                        runtime.transcriptNewest(conversation.address, 20).messages.any { !it.isOutbound && it.body == GREETING }
                    }
                    if (found == null) {
                        if (polls++ % 20 == 0) {
                            android.util.Log.i(TAG, "waiting: ${state?.directConversations?.map { it.peer.address.take(6) }} heard=${state?.peers?.filter { it.lastHeardAtMs != null }?.map { it.address.take(6) }}")
                        }
                        delay(POLL_MS)
                    }
                }
                found
            }
        }
        android.util.Log.i(TAG, "RECEIVED from=${conversation.peer.address}")
        val outcome = runBlocking { runtime.send(conversation.address, ANSWER, forwardSecret = null).await() }
        android.util.Log.i(TAG, "REPLIED $outcome")
        assertEquals(SendOutcome.Sent, outcome)
        // Stay attached while the answer goes out and its ack comes back.
        Thread.sleep(SETTLE_MS)
    }

    @Test
    fun guest() {
        assumeTrue("needs -e addPeerBridge guest", role == "guest")
        val link = InstrumentationRegistry.getArguments().getString("link")
        assumeTrue("needs -e link <link>", link != null)
        val runtime = launch(PHONE_PORT)
        // Conversations › New chat › New message (D11), then the import.
        waitForTag(Tags.CONVERSATIONS_ROOT)
        compose.waitUntil(TIMEOUT) { present(Tags.CONVERSATIONS_NEW_CHAT) || present(Tags.CONVERSATIONS_EMPTY_NEW_MESSAGE) }
        if (present(Tags.CONVERSATIONS_NEW_CHAT)) {
            compose.onNodeWithTag(Tags.CONVERSATIONS_NEW_CHAT).performClick()
            waitForTag(Tags.NEW_CHAT_MESSAGE)
            compose.onNodeWithTag(Tags.NEW_CHAT_MESSAGE).performClick()
        } else {
            compose.onNodeWithTag(Tags.CONVERSATIONS_EMPTY_NEW_MESSAGE).performClick()
        }
        waitForTag(Tags.ADD_PEER)
        compose.onNodeWithTag(Tags.ADD_PEER_FIELD).performTextReplacement(link!!)
        compose.onNodeWithTag(Tags.ADD_PEER_PREVIEW).performClick()
        waitForTag(Tags.IMPORT_SHEET)
        compose.onNodeWithTag(Tags.IMPORT_SAVE).performScrollTo().performClick()
        waitForTag(Tags.PEER_VERB_MESSAGE)
        val address = runtime.appState.value!!.peers.first { it.isSaved && !it.isCompanionRadio }.address
        android.util.Log.i(TAG, "SAVED $address")
        android.util.Log.i(TAG, "GUEST link=${runBlocking { runtime.shareUri().await() }}")
        runBlocking { awaitFile("go.txt") }
        compose.onNodeWithTag(Tags.PEER_VERB_MESSAGE).performClick()
        waitForTag(Tags.COMPOSER_FIELD)
        compose.onNodeWithTag(Tags.COMPOSER_FIELD).performTextReplacement(GREETING)
        waitForTag(Tags.COMPOSER_SEND)
        compose.onNodeWithTag(Tags.COMPOSER_SEND).performClick()
        runBlocking {
            withTimeout(TIMEOUT) {
                while (runtime.transcriptNewest(address, 20).messages.none { it.isOutbound && it.body == GREETING }) delay(POLL_MS)
            }
        }
        android.util.Log.i(TAG, "SENT ${runBlocking { runtime.transcriptNewest(address, 20).messages.last { it.isOutbound }.delivery }}")
        runBlocking {
            withTimeout(HEARD_TIMEOUT) {
                var polls = 0
                while (runtime.transcriptNewest(address, 20).messages.none { !it.isOutbound && it.body == ANSWER }) {
                    if (polls++ % 20 == 0) {
                        android.util.Log.i(TAG, "waiting: ${runtime.transcriptNewest(address, 20).messages.map { "${it.isOutbound}:${it.body}:${it.delivery}" }}")
                    }
                    delay(POLL_MS)
                }
            }
        }
        android.util.Log.i(TAG, "ANSWERED")
    }

    /** A file the run writes into this app's external files: its text, once there. */
    private suspend fun awaitFile(name: String): String {
        val file = java.io.File(context.getExternalFilesDir(null), name)
        withTimeout(HEARD_TIMEOUT) { while (!file.exists() || file.readText().isBlank()) delay(POLL_MS) }
        return file.readText().trim().also { file.delete() }
    }

    private companion object {
        const val TAG = "AddPeerBridgeTest"
        const val PHONE_PORT = 21838
        const val PEER_PORT = 21839
        const val GREETING = "Hello from api31"
        const val ANSWER = "Hello back from api36"
        const val TIMEOUT = 30_000L
        const val HEARD_TIMEOUT = 180_000L
        const val POLL_MS = 500L
        const val SETTLE_MS = 15_000L
    }
}
