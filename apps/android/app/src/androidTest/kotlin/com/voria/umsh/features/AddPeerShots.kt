package com.voria.umsh.features

import android.graphics.Bitmap
import android.view.inputmethod.InputMethodManager
import androidx.activity.ComponentActivity
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextReplacement
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.app.AppRoot
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.Tags
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
 * Screenshots of `add-peer.svg` 1–4 and `conversation-list.svg` 2 and 6
 * for the build report, in the real app root over the staged air. Off
 * unless the run passes `-e shots <suffix>`; they land in the app's
 * external files, under `shots/`.
 */
class AddPeerShots {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private val suffix: String? get() = InstrumentationRegistry.getArguments().getString("shots")

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

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
            withTimeout(TIMEOUT) { ready.runtime.appState.first { state -> state != null && state.directConversations.isNotEmpty() } }
            ready.runtime
        }
        compose.setContent { AppRoot(fresh.host) }
        return runtime
    }

    private fun present(tag: String) = compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()

    private fun waitFor(tag: String) = compose.waitUntil(TIMEOUT) { present(tag) }

    private fun hideKeyboard() = compose.runOnUiThread {
        val view = compose.activity.window.decorView
        view.context.getSystemService(InputMethodManager::class.java).hideSoftInputFromWindow(view.windowToken, 0)
    }

    private fun enter(input: String) {
        compose.onNodeWithTag(Tags.ADD_PEER_FIELD).performTextReplacement(input)
        compose.onNodeWithTag(Tags.ADD_PEER_PREVIEW).performClick()
        hideKeyboard()
    }

    private fun closeSheet() {
        InstrumentationRegistry.getInstrumentation().sendKeyDownUpSync(android.view.KeyEvent.KEYCODE_BACK)
        compose.waitUntil(TIMEOUT) { !present(Tags.IMPORT_SHEET) }
    }

    /** Boards 1–4: Add peer from the Peers list, a bad link, a signed preview, an unsigned one. */
    @Test
    fun addPeer() {
        start()
        waitFor(Tags.NAV_PEERS)
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitFor(Tags.PEERS_ADD)
        shot("peers-list-1-add-peer")
        compose.onNodeWithTag(Tags.PEERS_ADD).performClick()
        waitFor(Tags.ADD_PEER)
        shot("add-peer-1")

        enter("umsh:x:Mx4eTq8VbN3k")
        waitFor(Tags.ADD_PEER_PROBLEM)
        shot("add-peer-2")

        enter(ImportFixtures.signedLink(0x51).link)
        waitFor(Tags.IMPORT_SHEET)
        shot("add-peer-3")
        closeSheet()

        enter(ImportFixtures.unsignedLink(0x52))
        waitFor(Tags.IMPORT_SIGNATURE)
        shot("add-peer-4")
        closeSheet()

        // The interim channel line (§3.9) and a failed signature, for the record.
        enter(ImportFixtures.tamperedLink(0x53))
        waitFor(Tags.IMPORT_SIGNATURE)
        shot("add-peer-4-invalid")
        closeSheet()
        enter("umsh:gs:public")
        waitFor(Tags.ADD_PEER_PROBLEM)
        shot("add-peer-2-channel")
    }

    /** `conversation-list.svg` 6, New chat; then board 2, the empty list's New message. */
    @Test
    fun newChat() {
        val runtime = start()
        waitFor(Tags.CONVERSATIONS_NEW_CHAT)
        compose.onNodeWithTag(Tags.CONVERSATIONS_NEW_CHAT).performClick()
        waitFor(Tags.NEW_CHAT_MESSAGE)
        shot("conversation-list-6")
        InstrumentationRegistry.getInstrumentation().sendKeyDownUpSync(android.view.KeyEvent.KEYCODE_BACK)
        compose.waitUntil(TIMEOUT) { !present(Tags.NEW_CHAT_SHEET) }

        runBlocking { for (conversation in runtime.appState.value!!.conversations) runtime.deleteConversation(conversation.address).await() }
        waitFor(Tags.CONVERSATIONS_EMPTY_NEW_MESSAGE)
        shot("conversation-list-2")
    }

    private companion object {
        const val TIMEOUT = 30_000L
        const val SETTLE_MS = 800L
    }
}
