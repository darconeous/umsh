package com.voria.umsh.features

import android.Manifest
import android.content.ClipboardManager
import android.content.Intent
import android.os.Build
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performTextReplacement
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.MainActivity
import com.voria.umsh.app.SendOutcome
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.Copier
import com.voria.umsh.services.preferences.OnboardingStep
import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.RadioKind
import java.security.SecureRandom
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test

/**
 * Two phones over `make android-bridge ANDROID_BRIDGE_LAN=` (gated: `-e
 * channelBridge host|guest`), on a private channel this run creates; never
 * Public or EMERGENCY. The host (api36, the bridge's "peer" host on 21839)
 * creates the channel in Settings › Channels, copies its invitation from
 * Share, checks the clip is marked sensitive, and logs `READY
 * invitation=<text> sensitive=<bool>`. The guest (api31, "phone" on 21838)
 * logs `GUEST_READY`; the run then opens the invitation on it with `am
 * start`, and the guest joins it from Join channel, opens its conversation
 * and sends. The host answers the first message it hears there.
 *
 * Start the bridge only with 21837–21839 free beforehand, and check that the
 * listener on them is the bridge just started: a bridge already running may
 * have joined the LAN's group, and ports answering prove nothing about which
 * bridge answers.
 */
class ChannelBridgeTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createEmptyComposeRule()

    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val role: String? get() = InstrumentationRegistry.getArguments().getString("channelBridge")

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

    private fun openChannels() {
        waitForTag(Tags.NAV_SETTINGS)
        compose.onAllNodesWithTag(Tags.NAV_SETTINGS)[0].performClick()
        waitForTag(Tags.SETTINGS_CHANNELS)
        compose.onNodeWithTag(Tags.SETTINGS_CHANNELS).performClick()
        waitForTag(Tags.CHANNELS)
    }

    @Test
    fun host() {
        assumeTrue("needs -e channelBridge host", role == "host")
        val runtime = launch(PEER_PORT)
        val name = "bridge-" + ByteArray(2).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        openChannels()
        compose.onNodeWithTag(Tags.CHANNELS_ADD).performClick()
        waitForTag(Tags.CHANNELS_MENU_CREATE)
        compose.onNodeWithTag(Tags.CHANNELS_MENU_CREATE).performClick()
        waitForTag(Tags.CHANNEL_CREATE_NAME)
        compose.onNodeWithTag(Tags.CHANNEL_CREATE_NAME).performTextReplacement(name)
        compose.onNodeWithTag(Tags.CHANNEL_CREATE_ACTION).performClick()
        waitForTag(Tags.CHANNEL_PAGE)
        val channel = runtime.appState.value!!.channels.first { it.name == name }
        compose.onNodeWithTag(Tags.CHANNEL_VERB_SHARE).performClick()
        waitForTag(Tags.CHANNEL_SHARE_WARNING)
        compose.onNodeWithTag(Tags.QR_COPY_LINK).performScrollTo().performClick()
        compose.waitForIdle()
        var invitation: String? = null
        var sensitive = false
        instrumentation.runOnMainSync {
            val clipboard = context.getSystemService(ClipboardManager::class.java)
            invitation = clipboard.primaryClip?.getItemAt(0)?.text?.toString()
            sensitive = clipboard.primaryClipDescription?.extras?.getBoolean(Copier.SENSITIVE_EXTRA) == true
        }
        android.util.Log.i(TAG, "READY invitation=$invitation sensitive=$sensitive api=${Build.VERSION.SDK_INT}")
        assertTrue("the invitation was copied", invitation?.startsWith("umsh:gk:") == true)
        assertTrue("the invitation's clip is sensitive", sensitive)
        val address = runBlocking { runtime.openChannelConversation(channel.id).await() }
        android.util.Log.i(TAG, "HOST_CHANNEL hostChannels=${runtime.radio.value?.provisioning?.hostChannelCount}")

        runBlocking {
            withTimeout(HEARD_TIMEOUT) {
                var polls = 0
                while (runtime.transcriptNewest(address, 20).messages.none { !it.isOutbound && it.body == GREETING }) {
                    if (polls++ % 20 == 0) android.util.Log.i(TAG, "waiting: ${runtime.transcriptNewest(address, 20).messages.map { it.body }}")
                    delay(POLL_MS)
                }
            }
        }
        android.util.Log.i(TAG, "RECEIVED")
        val outcome = runBlocking { runtime.send(address, ANSWER, forwardSecret = null).await() }
        android.util.Log.i(TAG, "REPLIED $outcome")
        assertEquals(SendOutcome.Sent, outcome)
        Thread.sleep(SETTLE_MS)
    }

    @Test
    fun guest() {
        assumeTrue("needs -e channelBridge guest", role == "guest")
        val runtime = launch(PHONE_PORT)
        waitForTag(Tags.CONVERSATIONS_ROOT)
        android.util.Log.i(TAG, "GUEST_READY")
        // The run opens the invitation with `am start`: Join channel over Settings › Channels.
        compose.waitUntil(HEARD_TIMEOUT) { present(Tags.CHANNEL_PREVIEW) }
        compose.waitUntil(TIMEOUT) { present(Tags.CHANNEL_PREVIEW_LINE) }
        compose.onNodeWithTag(Tags.CHANNEL_JOIN_ACTION).performClick()
        compose.waitUntil(TIMEOUT) { !present(Tags.CHANNEL_JOIN) }
        val channel = runtime.appState.value!!.channels.first { it.name?.startsWith("bridge-") == true && it.joinedPhone }
        android.util.Log.i(TAG, "JOINED ${channel.name} hostChannels=${runtime.radio.value?.provisioning?.hostChannelCount}")
        waitForTag(Tags.CHANNELS_LIST)
        compose.onNodeWithTag(Tags.CHANNELS_LIST).performScrollToNode(hasTestTag(Tags.channelRow(channel.id)))
        compose.onNodeWithTag(Tags.channelRow(channel.id)).performClick()
        waitForTag(Tags.CHANNEL_VERB_CONVERSATION)
        compose.onNodeWithTag(Tags.CHANNEL_VERB_CONVERSATION).performClick()
        waitForTag(Tags.COMPOSER_FIELD)
        val address = runtime.appState.value!!.channels.first { it.id == channel.id }.conversationAddress!!
        compose.onNodeWithTag(Tags.COMPOSER_FIELD).performTextReplacement(GREETING)
        waitForTag(Tags.COMPOSER_SEND)
        compose.onNodeWithTag(Tags.COMPOSER_SEND).performClick()
        runBlocking {
            withTimeout(TIMEOUT) {
                while (runtime.transcriptNewest(address, 20).messages.none { it.isOutbound && it.body == GREETING }) delay(POLL_MS)
            }
        }
        android.util.Log.i(TAG, "SENT")
        runBlocking {
            withTimeout(HEARD_TIMEOUT) {
                var polls = 0
                while (runtime.transcriptNewest(address, 20).messages.none { !it.isOutbound && it.body == ANSWER }) {
                    if (polls++ % 20 == 0) android.util.Log.i(TAG, "waiting: ${runtime.transcriptNewest(address, 20).messages.map { "${it.isOutbound}:${it.body}" }}")
                    delay(POLL_MS)
                }
            }
        }
        android.util.Log.i(TAG, "ANSWERED")
    }

    private companion object {
        const val TAG = "ChannelBridgeTest"
        const val PHONE_PORT = 21838
        const val PEER_PORT = 21839
        const val GREETING = "Channel hello from api31"
        const val ANSWER = "Channel answer from api36"
        const val TIMEOUT = 30_000L
        const val HEARD_TIMEOUT = 180_000L
        const val POLL_MS = 500L
        const val SETTLE_MS = 15_000L
    }
}
