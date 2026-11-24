package com.voria.umsh.features

import android.Manifest
import android.graphics.Bitmap
import android.os.Build
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performSemanticsAction
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.app.AppRoot
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.UmshTheme
import com.voria.umsh.features.conversations.ChannelMember
import com.voria.umsh.features.conversations.MemberSheet
import com.voria.umsh.features.conversations.TranscriptWindow
import com.voria.umsh.models.NodeHint
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PreviewText.Sender
import com.voria.umsh.models.TranscriptRow
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
 * Screenshots of `conversation-info.svg` 1, 2, 5 and 6 for the build
 * report, with the Routing section absent (D6), in the real app root over
 * the staged air. Off unless the run passes `-e shots <suffix>`; they land
 * in the app's external files, under `shots/`. Nothing is sent.
 */
class ConversationInfoShots {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private val suffix: String? get() = InstrumentationRegistry.getArguments().getString("shots")
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext

    @Before
    fun onlyWhenAsked() = assumeTrue(suffix != null)

    private fun shot(name: String) {
        compose.waitForIdle()
        Thread.sleep(SETTLE_MS)
        val bitmap = instrumentation.uiAutomation.takeScreenshot() ?: return
        val directory = File(context.getExternalFilesDir(null), "shots").apply { mkdirs() }
        File(directory, "$name-$suffix.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    private fun start(): AppRuntime {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
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
            withTimeout(TIMEOUT) {
                ready.runtime.appState.first { state -> state?.channelConversations?.any { it.channel.name == "Trail Crew" } == true }
            }
            ready.runtime
        }
        compose.setContent { AppRoot(fresh.host) }
        return runtime
    }

    private fun present(tag: String) = compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()

    private fun waitFor(tag: String) = compose.waitUntil(TIMEOUT) { present(tag) }

    private fun openThread(address: String) {
        waitFor(Tags.CONVERSATION_LIST)
        compose.onNodeWithTag(Tags.CONVERSATION_LIST).performScrollToNode(hasTestTag(Tags.conversationRow(address)))
        // By its action, not a touch: on api31's short screen a scrolled-to top row sits under the bar.
        compose.onNodeWithTag(Tags.conversationRow(address)).performSemanticsAction(SemanticsActions.OnClick)
        waitFor(Tags.THREAD_TITLE)
    }

    private fun openInfo(address: String) {
        openThread(address)
        compose.onNodeWithTag(Tags.THREAD_TITLE).performClick()
        waitFor(Tags.CONVERSATION_INFO)
        compose.waitUntil(TIMEOUT) { present(Tags.CONVERSATION_INFO_MESSAGES) }
    }

    private fun AppRuntime.crew() = appState.value!!.channelConversations.first { it.channel.name == "Trail Crew" }.address

    /** Board 1 (light) and board 5, over Trail Crew, a named channel with messages. */
    @Test
    fun channelInfoAndClear() {
        val runtime = start()
        openInfo(runtime.crew())
        shot("conversation-info-1")
        compose.onNodeWithTag(Tags.CONVERSATION_INFO_CLEAR).performScrollTo().performClick()
        waitFor(Tags.CONFIRM_DIALOG)
        shot("conversation-info-5")
    }

    /** Board 2: EMERGENCY, Test messages and its statements. */
    @Test
    fun emergencyInfo() {
        val runtime = start()
        val emergency = runBlocking {
            val channel = runtime.appState.value!!.channels.first { it.canonicalName == "emergency" }
            runtime.openChannelConversation(channel.id).await()
        }
        openInfo(emergency)
        shot("conversation-info-2")
        compose.onNodeWithTag(Tags.CONVERSATION_INFO_STATEMENTS).performScrollTo()
        shot("conversation-info-2-end")
    }

    /** Board 6 from a member's avatar: one not saved (Request identity), then one saved (the header to its page). */
    @Test
    fun memberSheets() {
        val runtime = start()
        val crew = runtime.crew()
        val maya = runtime.appState.value!!.peers.first { it.advertisedName == "Maya Ortiz" }
        runBlocking { runtime.demotePeer(maya.address).await() }
        compose.waitUntil(TIMEOUT) { runtime.appState.value!!.peers.first { it.address == maya.address }.isSaved.not() }
        openThread(crew)
        waitFor(Tags.TRANSCRIPT)
        val window = runBlocking { TranscriptWindow().replacedBy(runtime.transcriptNewest(crew, TranscriptWindow.PAGE_SIZE), 0) }
        val row = window.rows.filterIsInstance<TranscriptRow.Message>()
            .last { it.message.senderAddress == maya.address && it.presentation.isLastInRun && !it.message.isStatus && !it.message.isDeleted }.key
        compose.onNodeWithTag(Tags.TRANSCRIPT).performScrollToNode(hasTestTag(Tags.message(row)))
        compose.onNode(hasTestTag(Tags.MEMBER_AVATAR) and hasAnyAncestor(hasTestTag(Tags.message(row))), useUnmergedTree = true).performClick()
        waitFor(Tags.MEMBER_SHEET)
        shot("conversation-info-6")
        runBlocking { runtime.promotePeer(maya.address).await() }
        compose.waitUntil(TIMEOUT) { present(Tags.MEMBER_PEER) }
        shot("conversation-info-6-saved")
    }

    /** Board 6 as drawn: "Member BtC5", a sender the staged air cannot make (every staged member names itself). */
    @Test
    fun unnamedMemberSheet() {
        val hint = NodeHint(Octets(byteArrayOf(0x12, 0x34, 0x56)), "BtC5")
        val member = ChannelMember(hint.octets, hint, address = null, handle = null, name = Sender.Hint("BtC5"), peer = null)
        runBlocking { fresh.host.preferences.setFallbackScheme(true) }
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.surface) {
                    Box(Modifier.fillMaxSize()) {
                        MemberSheet(member, requested = false, onRequestIdentity = {}, onOpenPeer = {}, onDismiss = {})
                    }
                }
            }
        }
        waitFor(Tags.MEMBER_SHEET)
        shot("conversation-info-6-unnamed")
    }

    private companion object {
        const val TIMEOUT = 30_000L
        const val SETTLE_MS = 800L
    }
}
