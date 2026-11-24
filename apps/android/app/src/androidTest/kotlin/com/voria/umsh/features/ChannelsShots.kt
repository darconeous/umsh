package com.voria.umsh.features

import android.Manifest
import android.graphics.Bitmap
import android.os.Build
import android.view.inputmethod.InputMethodManager
import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performTextReplacement
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.UiDevice
import com.voria.umsh.app.AppRoot
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.Tags
import com.voria.umsh.features.scanner.CameraPresence
import com.voria.umsh.features.scanner.LocalCameraPresence
import com.voria.umsh.features.scanner.LocalFrameSource
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
 * Screenshots of `channels.svg` 1–13, `new-channel-chat.svg` 1–3 and
 * `qr-scanner.svg` 4 for the build report, in the real app root over the
 * staged air. Off unless the run passes `-e shots <suffix>`; they land in
 * the app's external files, under `shots/`. Nothing is sent.
 */
class ChannelsShots {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private val suffix: String? get() = InstrumentationRegistry.getArguments().getString("shots")
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val camera = FakeFrameSource()

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
        instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.CAMERA)
        runBlocking {
            fresh.host.preferences.setFallbackScheme(true)
            fresh.host.preferences.setNotificationsAsked()
        }
        fresh.host.ensureRuntime(staging = true)
        val runtime = runBlocking {
            val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
            ready.runtime.setOnboarding(OnboardingStep.Done).await()
            withTimeout(TIMEOUT) { ready.runtime.radio.first { it?.carriesThisPhone == true } }
            withTimeout(TIMEOUT) { ready.runtime.appState.first { state -> state?.channels?.any { it.name == "Crew Leads" } == true } }
            ready.runtime
        }
        compose.setContent {
            CompositionLocalProvider(LocalFrameSource provides camera, LocalCameraPresence provides CameraPresence { true }) {
                AppRoot(fresh.host)
            }
        }
        return runtime
    }

    private fun present(tag: String) = compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()

    private fun waitFor(tag: String) = compose.waitUntil(TIMEOUT) { present(tag) }

    private fun waitGone(tag: String) = compose.waitUntil(TIMEOUT) { !present(tag) }

    private fun back() = UiDevice.getInstance(instrumentation).pressBack()

    private fun hideKeyboard() = compose.runOnUiThread {
        val view = compose.activity.window.decorView
        view.context.getSystemService(InputMethodManager::class.java).hideSoftInputFromWindow(view.windowToken, 0)
    }

    private fun AppRuntime.id(name: String) = appState.value!!.channels.first { it.name == name }.id

    private fun openChannels() {
        waitFor(Tags.NAV_SETTINGS)
        compose.onAllNodesWithTag(Tags.NAV_SETTINGS)[0].performClick()
        waitFor(Tags.SETTINGS_CHANNELS)
        compose.onNodeWithTag(Tags.SETTINGS_CHANNELS).performClick()
        waitFor(Tags.CHANNELS)
    }

    private fun lookUp(input: String) {
        compose.onNodeWithTag(Tags.CHANNEL_JOIN_FIELD).performTextReplacement(input)
        compose.onNodeWithTag(Tags.CHANNEL_LOOK_UP).performClick()
        hideKeyboard()
        waitFor(Tags.CHANNEL_PREVIEW)
    }

    /** "Fire"'s invitation, for a channel this phone no longer holds; with [keepAnother], another "Fire" held. */
    private fun fireInvitation(runtime: AppRuntime, keepAnother: Boolean): String = runBlocking {
        val fire = runtime.createPrivateChannel("Fire").await()
        val invitation = runtime.channelInvitation(fire).await()
        runtime.leaveChannel(fire).await()
        if (keepAnother) runtime.createPrivateChannel("Fire").await()
        invitation
    }

    /** Boards 1–2 and 10–13: the list, Add channel, a private page, its Leave and its invitation; Public's statements and link. */
    @Test
    fun listAndPages() {
        val runtime = start()
        runBlocking {
            runtime.joinChannel("hike-club", null, openConversation = false).await()
            runtime.createPrivateChannel("Fire").await()
            runtime.createPrivateChannel("Hot Topic").await()
        }
        openChannels()
        waitFor(Tags.channelRow(runtime.id("Hot Topic")))
        shot("channels-1")
        compose.onNodeWithTag(Tags.CHANNELS_ADD).performClick()
        waitFor(Tags.CHANNELS_MENU_JOIN)
        shot("channels-2")
        compose.onNodeWithTag(Tags.CHANNELS_ADD).performClick()
        waitGone(Tags.CHANNELS_MENU_JOIN)

        compose.onNodeWithTag(Tags.CHANNELS_LIST).performScrollToNode(hasTestTag(Tags.channelRow(runtime.id("Fire"))))
        compose.onNodeWithTag(Tags.channelRow(runtime.id("Fire"))).performClick()
        waitFor(Tags.CHANNEL_PAGE)
        shot("channels-10")
        compose.onNodeWithTag(Tags.CHANNEL_PAGE_LEAVE).performScrollTo().performClick()
        waitFor(Tags.CONFIRM_DIALOG)
        shot("channels-12")
        compose.onNodeWithTag(Tags.CONFIRM_CANCEL).performClick()
        waitGone(Tags.CONFIRM_DIALOG)
        compose.onNodeWithTag(Tags.CHANNEL_VERB_SHARE).performScrollTo().performClick()
        waitFor(Tags.CHANNEL_SHARE_WARNING)
        waitFor(Tags.QR_IMAGE)
        shot("channels-13")
        back()
        waitGone(Tags.QR_SHEET)
        back()
        waitFor(Tags.CHANNELS_LIST)

        compose.onNodeWithTag(Tags.channelRow(runtime.id("Public"))).performClick()
        waitFor(Tags.CHANNEL_PAGE_STATEMENTS)
        compose.onNodeWithTag(Tags.CHANNEL_PAGE_STATEMENTS).performScrollTo()
        shot("channels-11")
        compose.onNodeWithTag(Tags.CHANNEL_PAGE_LEAVE).performScrollTo().performClick()
        waitFor(Tags.CONFIRM_DIALOG)
        shot("channels-12-public")
        compose.onNodeWithTag(Tags.CONFIRM_CANCEL).performClick()
        waitGone(Tags.CONFIRM_DIALOG)
        compose.onNodeWithTag(Tags.CHANNEL_VERB_SHARE).performScrollTo().performClick()
        waitFor(Tags.QR_IMAGE)
        shot("channels-13-public")
    }

    /** Boards 4–9: New channel, Join with suggestions, then the previews: public, private (and its key shown), already joined, a conflict. */
    @Test
    fun createAndJoin() {
        val runtime = start()
        val invitation = fireInvitation(runtime, keepAnother = false)
        runBlocking {
            runtime.leaveChannel(runtime.id("Public")).await()
            runtime.joinChannel("hike-club", null, openConversation = false).await()
        }
        openChannels()
        compose.onNodeWithTag(Tags.CHANNELS_ADD).performClick()
        waitFor(Tags.CHANNELS_MENU_CREATE)
        compose.onNodeWithTag(Tags.CHANNELS_MENU_CREATE).performClick()
        waitFor(Tags.CHANNEL_CREATE_NAME)
        compose.onNodeWithTag(Tags.CHANNEL_CREATE_NAME).performTextReplacement("Fire")
        hideKeyboard()
        shot("channels-4")
        back()
        waitGone(Tags.CHANNEL_CREATE)

        compose.onNodeWithTag(Tags.CHANNELS_ADD).performClick()
        waitFor(Tags.CHANNELS_MENU_JOIN)
        compose.onNodeWithTag(Tags.CHANNELS_MENU_JOIN).performClick()
        waitFor(Tags.CHANNEL_JOIN_FIELD)
        hideKeyboard()
        shot("channels-5")
        lookUp("ridge-runners")
        shot("channels-6")
        lookUp(invitation)
        shot("channels-7")
        compose.onNodeWithTag(Tags.CHANNEL_KEY_EYE).performClick()
        waitFor(Tags.CHANNEL_KEY_VALUE)
        shot("channels-7-key")
        lookUp("hike-club")
        waitFor(Tags.CHANNEL_PREVIEW_JOINED)
        shot("channels-8")
        runBlocking { runtime.createPrivateChannel("Fire").await() }
        lookUp(invitation)
        waitFor(Tags.CHANNEL_PREVIEW_CONFLICT)
        shot("channels-9")
    }

    /** Board 3: no channels joined. */
    @Test
    fun empty() {
        val runtime = start()
        runBlocking {
            for (channel in runtime.appState.value!!.channels.filter { it.joinedPhone }) runtime.leaveChannel(channel.id).await()
        }
        openChannels()
        waitFor(Tags.CHANNELS_EMPTY)
        shot("channels-3")
    }

    /** `new-channel-chat.svg` 1–2 (3 is 1 in the dark run), then `qr-scanner.svg` 4 over Conversations. */
    @Test
    fun newChannelChatAndScannedCode() {
        val runtime = start()
        runBlocking {
            runtime.createPrivateChannel("Hot Topic").await()
            runtime.createPrivateChannel("Ridge SAR").await()
            runtime.joinChannel("trail-ops", null, openConversation = false).await()
        }
        waitFor(Tags.CONVERSATIONS_NEW_CHAT)
        compose.onNodeWithTag(Tags.CONVERSATIONS_NEW_CHAT).performClick()
        waitFor(Tags.NEW_CHAT_CHANNEL)
        compose.onNodeWithTag(Tags.NEW_CHAT_CHANNEL).performClick()
        waitFor(Tags.CHANNEL_CHOOSER)
        waitFor(Tags.chooserChannel(runtime.id("trail-ops")))
        shot("new-channel-chat-1")
        back()
        waitGone(Tags.CHANNEL_CHOOSER)
        runBlocking {
            for (channel in runtime.appState.value!!.channels.filter { it.joinedPhone && it.conversationAddress == null }) {
                runtime.openChannelConversation(channel.id).await()
            }
        }
        compose.onNodeWithTag(Tags.CONVERSATIONS_NEW_CHAT).performClick()
        waitFor(Tags.NEW_CHAT_CHANNEL)
        compose.onNodeWithTag(Tags.NEW_CHAT_CHANNEL).performClick()
        waitFor(Tags.CHANNEL_CHOOSER_NONE)
        shot("new-channel-chat-2")
        back()
        waitGone(Tags.CHANNEL_CHOOSER)

        camera.feeding = true
        camera.show("umsh:gs:ridge-runners")
        compose.onNodeWithTag(Tags.CONVERSATIONS_SCAN).performClick()
        waitFor(Tags.CHANNEL_SHEET)
        waitFor(Tags.CHANNEL_PREVIEW_NAME)
        shot("qr-scanner-4")
    }

    private companion object {
        const val TIMEOUT = 30_000L
        const val SETTLE_MS = 800L
    }
}
