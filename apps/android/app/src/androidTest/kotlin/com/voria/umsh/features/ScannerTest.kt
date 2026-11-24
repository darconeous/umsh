package com.voria.umsh.features

import android.Manifest
import android.content.ClipboardManager
import androidx.activity.ComponentActivity
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.StateRestorationTester
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.longClick
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performTouchInput
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.Destination
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.LocalAppCoreHost
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.ScanTarget
import com.voria.umsh.app.ShellState
import com.voria.umsh.app.Tags
import com.voria.umsh.app.TestWindows
import com.voria.umsh.app.UmshKey
import com.voria.umsh.app.UmshShell
import com.voria.umsh.app.rememberShellState
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.core.nodeUriForAddress
import com.voria.umsh.designsystem.LocalWindowOverride
import com.voria.umsh.designsystem.UmshTheme
import com.voria.umsh.features.scanner.CameraPresence
import com.voria.umsh.features.scanner.CameraStatus
import com.voria.umsh.features.scanner.IN_USE_GRACE
import com.voria.umsh.features.scanner.LocalCameraPresence
import com.voria.umsh.features.scanner.LocalFrameSource
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * The QR scanner (`qr-scanner.svg` 1–3) and peer sharing (`share.svg`
 * 1–2) over the staging core, the camera's frames made by the test
 * ([FakeFrameSource]) and its presence forced on, so ZXing reads drawn
 * codes through the scanner's own analysis. The camera permission is
 * granted; its ask is [ScannerPermissionTest]'s.
 */
class ScannerTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private lateinit var shell: ShellState
    private val camera = FakeFrameSource()

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun grantCamera() {
        // Granting, unlike revoking, leaves the process running.
        InstrumentationRegistry.getInstrumentation().uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.CAMERA)
    }

    private fun runtime(): AppRuntime = runBlocking {
        fresh.host.preferences.setFallbackScheme(true)
        fresh.host.ensureRuntime(staging = true)
        val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
        val runtime = ready.runtime
        withTimeout(TIMEOUT) { runtime.lifecycle.first { it is MobileAppLifecycle.Running } }
        withTimeout(TIMEOUT) {
            runtime.appState.first { state -> state != null && state.directConversations.isNotEmpty() && state.peers.any { it.isSaved && !it.isCompanionRadio } }
        }
        runtime
    }

    private fun show(runtime: AppRuntime, hasCamera: Boolean = true, restoration: StateRestorationTester? = null) {
        val content: @Composable () -> Unit = {
            UmshTheme(fallbackScheme = true) {
                CompositionLocalProvider(
                    LocalAppRuntime provides runtime,
                    LocalAppCoreHost provides fresh.host,
                    LocalWindowOverride provides TestWindows.Phone,
                    LocalFrameSource provides camera,
                    LocalCameraPresence provides CameraPresence { hasCamera },
                ) {
                    val state = rememberShellState()
                    shell = state
                    UmshShell(state)
                }
            }
        }
        if (restoration != null) restoration.setContent(content) else compose.setContent(content)
        waitForTag(Tags.CONVERSATIONS_ROOT)
    }

    private fun present(tag: String) = compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()

    private fun count(tag: String) = compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().size

    private fun waitForTag(tag: String) = compose.waitUntil(TIMEOUT) { present(tag) }

    private fun waitGone(tag: String) = compose.waitUntil(TIMEOUT) { !present(tag) }

    private fun text(tag: String): String = compose.onNodeWithTag(tag, useUnmergedTree = true).fetchSemanticsNode().config
        .getOrNull(SemanticsProperties.Text)?.joinToString("") { it.text }.orEmpty()

    private fun string(id: Int) = context.getString(id)

    private fun clip(): String? =
        context.getSystemService(ClipboardManager::class.java).primaryClip?.getItemAt(0)?.text?.toString()

    /** The pill is one node for TalkBack: its text is merged into it. */
    private fun pill(): String = compose.onNodeWithTag(Tags.SCANNER_PILL).fetchSemanticsNode().config
        .getOrNull(SemanticsProperties.Text)?.joinToString("") { it.text }.orEmpty()

    /** The held-camera line, one node like the pill. */
    private fun inUseLine(): String = compose.onNodeWithTag(Tags.SCANNER_IN_USE).fetchSemanticsNode().config
        .getOrNull(SemanticsProperties.Text)?.joinToString("") { it.text }.orEmpty()

    /** [tag] does not appear at any point for [millis]. */
    private fun assertNeverShown(tag: String, millis: Long) {
        val until = System.currentTimeMillis() + millis
        while (System.currentTimeMillis() < until) {
            compose.waitForIdle()
            assertTrue("$tag appeared", !present(tag))
            Thread.sleep(50)
        }
    }

    private fun peersTab() {
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitForTag(Tags.PEERS_SCAN)
    }

    private fun scanFrom(tag: String) {
        compose.onNodeWithTag(tag).performClick()
        waitForTag(Tags.SCANNER_VIEWFINDER)
    }

    /** A node no one here has heard of. */
    private fun strangerLink(seed: Int = 0x71) = nodeUriForAddress(ImportFixtures.address(seed))

    private fun row(address: String): SemanticsNodeInteraction {
        compose.onNodeWithTag(Tags.PEERS_LIST).performScrollToNode(hasTestTag(Tags.peerRow(address)))
        return compose.onNodeWithTag(Tags.peerRow(address))
    }

    private fun closeSheet() {
        compose.waitForIdle()
        InstrumentationRegistry.getInstrumentation().sendKeyDownUpSync(android.view.KeyEvent.KEYCODE_BACK)
    }

    // --- The scanner -------------------------------------------------------

    /**
     * Board 3: a node code closes the scanner and opens the import preview
     * over Peers, once, however many frames still hold it; dismissing
     * returns to Peers and nothing opens again.
     */
    @Test
    fun aNodeCodeOpensThePreviewOverPeersOnce() {
        show(runtime())
        peersTab()
        scanFrom(Tags.PEERS_SCAN)
        assertEquals(UmshKey.Scanner(ScanTarget.Root, Destination.Peers), shell.appStack.last())
        // Fed again and again until the scanner closes, and the camera is gone with it.
        camera.show(strangerLink())
        waitForTag(Tags.IMPORT_SHEET)
        waitGone(Tags.SCANNER)
        assertEquals(1, count(Tags.IMPORT_SHEET))
        assertEquals(listOf(UmshKey.Shell), shell.appStack.toList())
        assertEquals(listOf(UmshKey.PeersRoot), shell.stacks.getValue(Destination.Peers).toList())
        assertNull(shell.pendingScan)
        assertTrue(present(Tags.PEERS_ROOT))

        closeSheet()
        waitGone(Tags.IMPORT_SHEET)
        Thread.sleep(SETTLE_MS)
        compose.onNodeWithTag(Tags.IMPORT_SHEET).assertDoesNotExist()
        compose.onNodeWithTag(Tags.SCANNER).assertDoesNotExist()
    }

    /** Save peer from a scanned code: saved, and its page opens on Peers. */
    @Test
    fun savingAScannedCodeOpensThePage() {
        val runtime = runtime()
        show(runtime)
        peersTab()
        scanFrom(Tags.PEERS_SCAN)
        val address = ImportFixtures.address(0x72)
        camera.show(nodeUriForAddress(address))
        waitForTag(Tags.IMPORT_SAVE)
        compose.onNodeWithTag(Tags.IMPORT_SAVE).performScrollTo().performClick()
        waitForTag(Tags.PEER_PAGE)
        assertEquals(UmshKey.PeerPage(address, Destination.Peers), shell.stacks.getValue(Destination.Peers).last())
        assertTrue(runtime.appState.value!!.peers.first { it.address == address }.isSaved)
    }

    /** A saved node's code opens its page instead of the preview. */
    @Test
    fun aSavedNodesCodeOpensItsPage() {
        val runtime = runtime()
        val saved = runtime.appState.value!!.peers.first { it.isSaved && !it.isCompanionRadio }
        show(runtime)
        peersTab()
        scanFrom(Tags.PEERS_SCAN)
        camera.show(nodeUriForAddress(saved.address))
        waitForTag(Tags.PEER_PAGE)
        compose.onNodeWithTag(Tags.IMPORT_SHEET).assertDoesNotExist()
        assertEquals(UmshKey.PeerPage(saved.address, Destination.Peers), shell.stacks.getValue(Destination.Peers).last())
    }

    /** This phone's own code opens Your identity (DP3-62), not a preview. */
    @Test
    fun ownCodeOpensYourIdentity() {
        val runtime = runtime()
        show(runtime)
        scanFrom(Tags.CONVERSATIONS_SCAN)
        camera.show(nodeUriForAddress(runtime.identity.value.address))
        waitForTag(Tags.YOUR_IDENTITY)
        compose.onNodeWithTag(Tags.IMPORT_SHEET).assertDoesNotExist()
    }

    /** From Conversations, the preview opens over Conversations (board 3's note), and Message opens the thread. */
    @Test
    fun scanFromConversations() {
        show(runtime())
        scanFrom(Tags.CONVERSATIONS_SCAN)
        camera.show(strangerLink(0x73))
        waitForTag(Tags.IMPORT_MESSAGE)
        assertEquals(Destination.Conversations, shell.selected)
        assertTrue(present(Tags.CONVERSATIONS_ROOT))
        compose.onNodeWithTag(Tags.IMPORT_MESSAGE).performScrollTo().performClick()
        compose.waitUntil(TIMEOUT) { shell.stacks.getValue(Destination.Conversations).last() is UmshKey.Thread }
    }

    /** The Add peer field's scan button: the field is filled with the code and previewed. */
    @Test
    fun theAddPeerFieldsScanFillsTheField() {
        show(runtime())
        peersTab()
        compose.onNodeWithTag(Tags.PEERS_ADD).performClick()
        waitForTag(Tags.ADD_PEER_SCAN)
        scanFrom(Tags.ADD_PEER_SCAN)
        assertEquals(UmshKey.Scanner(ScanTarget.AddPeerField, Destination.Peers), shell.appStack.last())
        val link = strangerLink(0x74)
        camera.show(link)
        waitForTag(Tags.IMPORT_SHEET)
        assertEquals(UmshKey.AddPeer(Destination.Peers), shell.stacks.getValue(Destination.Peers).last())
        closeSheet()
        waitGone(Tags.IMPORT_SHEET)
        val field = compose.onNodeWithTag(Tags.ADD_PEER_FIELD).fetchSemanticsNode().config.getOrNull(SemanticsProperties.EditableText)?.text
        assertEquals(link, field)
    }

    /** Board 2: any other code is a pill, the scanner keeps running, and the pill goes once the code is out of the frame. */
    @Test
    fun anotherCodeIsAPillUntilItLeaves() {
        show(runtime())
        peersTab()
        scanFrom(Tags.PEERS_SCAN)
        camera.show("https://example.org/trailhead")
        waitForTag(Tags.SCANNER_PILL)
        assertEquals(string(R.string.scanner_not_umsh), pill())
        assertEquals(LiveRegionMode.Polite, compose.onNodeWithTag(Tags.SCANNER_PILL).fetchSemanticsNode().config.getOrNull(SemanticsProperties.LiveRegion))
        // A bare address is not a UMSH code either.
        camera.show(ImportFixtures.address(0x75))
        Thread.sleep(SETTLE_MS)
        assertEquals(string(R.string.scanner_not_umsh), pill())
        camera.show(null)
        waitGone(Tags.SCANNER_PILL)
        assertTrue(present(Tags.SCANNER_VIEWFINDER))
        assertEquals(UmshKey.Scanner(ScanTarget.Root, Destination.Peers), shell.appStack.last())
    }

    /**
     * The pill says what is in the frame, so it goes with the frames: under
     * a camera that is opening again (held elsewhere for a moment) and on
     * the camera-off page, and it comes back only from frames that show it.
     */
    @Test
    fun aPillLeavesWithTheCamera() {
        show(runtime())
        scanFrom(Tags.CONVERSATIONS_SCAN)
        camera.show("https://example.org/trailhead")
        waitForTag(Tags.SCANNER_PILL)
        camera.status.value = CameraStatus.Opening
        waitGone(Tags.SCANNER_PILL)
        assertTrue(present(Tags.SCANNER_VIEWFINDER))
        camera.status.value = null
        waitForTag(Tags.SCANNER_PILL)
        camera.status.value = CameraStatus.AccessOff
        waitForTag(Tags.SCANNER_CAMERA_OFF)
        compose.onNodeWithTag(Tags.SCANNER_PILL).assertDoesNotExist()
        camera.show(null)
        camera.status.value = null
        compose.onNodeWithTag(Tags.SCANNER_ALLOW).performClick()
        waitForTag(Tags.SCANNER_VIEWFINDER)
        Thread.sleep(SETTLE_MS)
        compose.onNodeWithTag(Tags.SCANNER_PILL).assertDoesNotExist()
    }

    /**
     * A channel code (`qr-scanner.svg` 4): the scanner closes and the
     * channel's join preview opens over the root; Join channel joins and
     * opens the conversation (staged air: nothing is sent).
     */
    @Test
    fun aChannelCodeOpensItsPreview() {
        val runtime = runtime()
        show(runtime)
        scanFrom(Tags.CONVERSATIONS_SCAN)
        camera.show("umsh:gs:ridge-runners")
        waitGone(Tags.SCANNER)
        waitForTag(Tags.CHANNEL_SHEET)
        compose.waitUntil(TIMEOUT) { present(Tags.CHANNEL_PREVIEW_NAME) }
        compose.onNodeWithTag(Tags.IMPORT_SHEET).assertDoesNotExist()
        compose.onNodeWithTag(Tags.CONVERSATIONS_ROOT).assertExists()

        // Join channel joins and opens the new conversation on the stack the scan began on.
        compose.onNodeWithTag(Tags.CHANNEL_SHEET_JOIN).performClick()
        waitGone(Tags.CHANNEL_SHEET)
        compose.waitUntil(TIMEOUT) { shell.stacks.getValue(Destination.Conversations).last() is UmshKey.Thread }
        assertEquals(Destination.Conversations, shell.selected)
        val thread = shell.stacks.getValue(Destination.Conversations).last() as UmshKey.Thread
        val joined = runtime.appState.value!!.channels.first { it.canonicalName == "ridge-runners" }
        assertTrue(joined.joinedPhone)
        assertEquals(joined.conversationAddress, thread.address)
    }

    /** Join channel's scan button (`channels.svg` 5): the code fills the field and is looked up in place. */
    @Test
    fun joinChannelsScanFillsTheFieldAndLooksItUp() {
        show(runtime())
        compose.runOnIdle { shell.openChannelJoin() }
        waitForTag(Tags.CHANNEL_JOIN_SCAN)
        scanFrom(Tags.CHANNEL_JOIN_SCAN)
        assertEquals(UmshKey.Scanner(ScanTarget.JoinChannelField, Destination.Settings), shell.appStack.last())
        camera.show("umsh:gs:ridge-runners")
        waitGone(Tags.SCANNER)
        compose.waitUntil(TIMEOUT) { present(Tags.CHANNEL_PREVIEW_NAME) }
        val field = compose.onNodeWithTag(Tags.CHANNEL_JOIN_FIELD).fetchSemanticsNode().config.getOrNull(SemanticsProperties.EditableText)?.text
        assertEquals("umsh:gs:ridge-runners", field)
        compose.onNodeWithTag(Tags.CHANNEL_SHEET).assertDoesNotExist()
        assertEquals(UmshKey.ChannelJoin(), shell.appStack.last())
    }

    /** Close and Back both return to where the scan began, as it was. */
    @Test
    fun closeAndBackReturn() {
        show(runtime())
        peersTab()
        scanFrom(Tags.PEERS_SCAN)
        compose.onNodeWithTag(Tags.SCANNER_CLOSE).performClick()
        waitGone(Tags.SCANNER)
        assertEquals(listOf(UmshKey.Shell), shell.appStack.toList())
        assertEquals(Destination.Peers, shell.selected)
        scanFrom(Tags.PEERS_SCAN)
        closeSheet()
        waitGone(Tags.SCANNER)
        assertEquals(Destination.Peers, shell.selected)
    }

    /**
     * Camera access off (quick settings, or disabled by policy): the page
     * says so, not a black viewfinder, and Allow camera binds again.
     */
    @Test
    fun cameraAccessOffSaysSoAndAllowTriesAgain() {
        show(runtime())
        scanFrom(Tags.CONVERSATIONS_SCAN)
        val first = camera.binds.get()
        camera.status.value = CameraStatus.AccessOff
        waitForTag(Tags.SCANNER_CAMERA_OFF)
        assertTrue(compose.onAllNodesWithText(string(R.string.scanner_camera_off)).fetchSemanticsNodes().isNotEmpty())
        compose.onNodeWithTag(Tags.SCANNER_VIEWFINDER).assertDoesNotExist()
        compose.onNodeWithTag(Tags.SCANNER_TORCH).assertDoesNotExist()
        compose.onNodeWithTag(Tags.SCANNER_RETRY).assertDoesNotExist()
        camera.status.value = null
        compose.onNodeWithTag(Tags.SCANNER_ALLOW).performClick()
        waitForTag(Tags.SCANNER_VIEWFINDER)
        assertTrue(camera.binds.get() > first)
    }

    /**
     * Any other critical camera error (or no camera to bind): board 3's
     * layout with a plain "Camera unavailable", no Allow camera, since
     * access is not what is wrong, and Try again binds again.
     */
    @Test
    fun anotherCameraFailureSaysUnavailableAndTriesAgain() {
        show(runtime())
        scanFrom(Tags.CONVERSATIONS_SCAN)
        val first = camera.binds.get()
        camera.status.value = CameraStatus.Unavailable
        waitForTag(Tags.SCANNER_CAMERA_OFF)
        assertTrue(compose.onAllNodesWithText(string(R.string.scanner_camera_unavailable)).fetchSemanticsNodes().isNotEmpty())
        assertTrue(compose.onAllNodesWithText(string(R.string.scanner_camera_off)).fetchSemanticsNodes().isEmpty())
        compose.onNodeWithTag(Tags.SCANNER_ALLOW).assertDoesNotExist()
        compose.onNodeWithTag(Tags.SCANNER_VIEWFINDER).assertDoesNotExist()
        camera.status.value = null
        compose.onNodeWithTag(Tags.SCANNER_RETRY).performClick()
        waitForTag(Tags.SCANNER_VIEWFINDER)
        assertTrue(camera.binds.get() > first)
    }

    /**
     * Another app holding the camera past the grace period: the dark
     * viewfinder stays, with one line in the pill's place, and no torch
     * and no camera-off page. The line goes once the camera opens.
     */
    @Test
    fun aCameraHeldElsewhereSaysSoAndWaits() {
        show(runtime())
        scanFrom(Tags.CONVERSATIONS_SCAN)
        camera.status.value = CameraStatus.InUse
        waitForTag(Tags.SCANNER_IN_USE)
        assertEquals(string(R.string.scanner_camera_in_use), inUseLine())
        assertTrue(present(Tags.SCANNER_VIEWFINDER))
        compose.onNodeWithTag(Tags.SCANNER_CAMERA_OFF).assertDoesNotExist()
        compose.onNodeWithTag(Tags.SCANNER_TORCH).assertDoesNotExist()
        camera.status.value = null
        waitGone(Tags.SCANNER_IN_USE)
        waitForTag(Tags.SCANNER_TORCH)
    }

    /** A camera freed within the grace period (the Camera app just closed) says nothing. */
    @Test
    fun aBriefHoldSaysNothing() {
        show(runtime())
        scanFrom(Tags.CONVERSATIONS_SCAN)
        camera.status.value = CameraStatus.InUse
        Thread.sleep(IN_USE_GRACE.inWholeMilliseconds / 4)
        camera.status.value = null
        waitForTag(Tags.SCANNER_TORCH)
        assertNeverShown(Tags.SCANNER_IN_USE, IN_USE_GRACE.inWholeMilliseconds + SETTLE_MS)
    }

    /** A line already shown stays through a rotation, with no second wait. */
    @Test
    fun aShownLineStaysThroughARotation() {
        val restoration = StateRestorationTester(compose)
        show(runtime(), restoration = restoration)
        scanFrom(Tags.CONVERSATIONS_SCAN)
        camera.status.value = CameraStatus.InUse
        waitForTag(Tags.SCANNER_IN_USE)
        restoration.emulateSavedInstanceStateRestore()
        compose.waitForIdle()
        assertTrue(present(Tags.SCANNER_IN_USE))
        camera.status.value = null
        waitGone(Tags.SCANNER_IN_USE)
    }

    /**
     * CameraX retries while the camera is held, passing through opening
     * each time: the wait is not restarted, the line appears on time, and
     * once shown it does not blink. It goes when the camera opens.
     */
    @Test
    fun retriesWhileHeldStillShowTheLine() {
        show(runtime())
        scanFrom(Tags.CONVERSATIONS_SCAN)
        val retries = AtomicBoolean(true)
        val retrying = thread {
            while (retries.get()) {
                camera.status.value = CameraStatus.InUse
                Thread.sleep(RETRY_MS)
                camera.status.value = CameraStatus.Opening
                Thread.sleep(RETRY_MS)
            }
        }
        try {
            // Retries every 2 × RETRY_MS, well inside the grace period: a wait restarted by each would never end.
            compose.waitUntil(IN_USE_GRACE.inWholeMilliseconds + TIMEOUT / 4) { present(Tags.SCANNER_IN_USE) }
            val until = System.currentTimeMillis() + 4 * RETRY_MS
            while (System.currentTimeMillis() < until) {
                compose.waitForIdle()
                assertTrue(present(Tags.SCANNER_IN_USE))
                Thread.sleep(RETRY_MS / 4)
            }
        } finally {
            retries.set(false)
            retrying.join()
        }
        camera.status.value = null
        waitGone(Tags.SCANNER_IN_USE)
    }

    /** §3.10: the viewfinder is described, the torch has a state, the pill is polite (above). */
    @Test
    fun whatTalkBackReads() {
        show(runtime())
        scanFrom(Tags.CONVERSATIONS_SCAN)
        val viewfinder = compose.onNodeWithTag(Tags.SCANNER_VIEWFINDER).fetchSemanticsNode().config
        assertEquals(listOf(string(R.string.scanner_viewfinder_description)), viewfinder.getOrNull(SemanticsProperties.ContentDescription))
        waitForTag(Tags.SCANNER_TORCH)
        fun torchState() = compose.onNodeWithTag(Tags.SCANNER_TORCH).fetchSemanticsNode().config.getOrNull(SemanticsProperties.StateDescription)
        assertEquals(string(R.string.scanner_torch_off), torchState())
        compose.onNodeWithTag(Tags.SCANNER_TORCH).performClick()
        compose.waitUntil(TIMEOUT) { torchState() == string(R.string.scanner_torch_on) }
        val close = compose.onNodeWithTag(Tags.SCANNER_CLOSE).fetchSemanticsNode().config
        assertEquals(listOf(string(R.string.action_close)), close.getOrNull(SemanticsProperties.ContentDescription))
        // A camera held elsewhere: its line is one polite node, read once.
        camera.status.value = CameraStatus.InUse
        waitForTag(Tags.SCANNER_IN_USE)
        assertEquals(string(R.string.scanner_camera_in_use), inUseLine())
        assertEquals(LiveRegionMode.Polite, compose.onNodeWithTag(Tags.SCANNER_IN_USE).fetchSemanticsNode().config.getOrNull(SemanticsProperties.LiveRegion))
        camera.status.value = null
        waitGone(Tags.SCANNER_IN_USE)
    }

    /** Without a camera there is nothing to scan with: no Scan on either root or in Add peer's field (§3.9). */
    @Test
    fun noCameraNoScan() {
        show(runtime(), hasCamera = false)
        compose.onNodeWithTag(Tags.CONVERSATIONS_SEARCH).assertExists()
        compose.onNodeWithTag(Tags.CONVERSATIONS_SCAN).assertDoesNotExist()
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitForTag(Tags.PEERS_SEARCH)
        compose.onNodeWithTag(Tags.PEERS_SCAN).assertDoesNotExist()
        compose.onNodeWithTag(Tags.PEERS_ADD).performClick()
        waitForTag(Tags.ADD_PEER_FIELD)
        compose.onNodeWithTag(Tags.ADD_PEER_SCAN).assertDoesNotExist()
    }

    // --- Sharing -----------------------------------------------------------

    /** `share.svg` 1: Share in the peer page's top bar opens the node's code, with Copy link and Share ready. */
    @Test
    fun aPeersPageSharesItsLink() {
        val runtime = runtime()
        val saved = runtime.appState.value!!.peers.first { it.isSaved && !it.isCompanionRadio }
        show(runtime)
        peersTab()
        row(saved.address).performClick()
        waitForTag(Tags.PEER_SHARE)
        compose.onNodeWithTag(Tags.PEER_SHARE).performClick()
        waitForTag(Tags.QR_IMAGE)
        compose.waitUntil(TIMEOUT) {
            compose.onAllNodesWithTag(Tags.QR_COPY_LINK).fetchSemanticsNodes().any { SemanticsActions.OnClick in it.config && SemanticsProperties.Disabled !in it.config }
        }
        compose.onNodeWithTag(Tags.QR_SHARE).assertExists()
        // D4: the node's own bare link, not this phone's.
        compose.onNodeWithTag(Tags.QR_COPY_LINK).performClick()
        compose.waitUntil(TIMEOUT) { clip() == nodeUriForAddress(saved.address) }
        closeSheet()
        waitGone(Tags.QR_SHEET)
        assertTrue(present(Tags.PEER_PAGE))
    }

    /** `share.svg` 2's note: a Peers row's long press offers the same Share. */
    @Test
    fun aRowsLongPressShares() {
        val runtime = runtime()
        val saved = runtime.appState.value!!.peers.first { it.isSaved && !it.isCompanionRadio }
        show(runtime)
        peersTab()
        row(saved.address).performTouchInput { longClick() }
        waitForTag(Tags.PEER_MENU_SHARE)
        compose.onNodeWithTag(Tags.PEER_MENU_SHARE).performClick()
        waitForTag(Tags.QR_IMAGE)
        assertEquals(listOf(UmshKey.PeersRoot), shell.stacks.getValue(Destination.Peers).toList())
    }

    /** A node that leaves the list takes its share sheet with it, and the sheet stays shut when the node is back. */
    @Test
    fun aSharedNodeThatLeavesClosesItsSheet() {
        val runtime = runtime()
        val saved = runtime.appState.value!!.peers.first { it.isSaved && !it.isCompanionRadio }
        show(runtime)
        peersTab()
        row(saved.address).performTouchInput { longClick() }
        waitForTag(Tags.PEER_MENU_SHARE)
        compose.onNodeWithTag(Tags.PEER_MENU_SHARE).performClick()
        waitForTag(Tags.QR_IMAGE)
        runBlocking { runtime.deletePeer(saved.address, withConversation = true).await() }
        waitGone(Tags.QR_SHEET)
        runBlocking { runtime.savePeer(nodeUriForAddress(saved.address), alias = null, startConversation = false).await() }
        compose.waitUntil(TIMEOUT) { runtime.appState.value!!.peers.any { it.address == saved.address } }
        Thread.sleep(SETTLE_MS)
        compose.onNodeWithTag(Tags.QR_SHEET).assertDoesNotExist()
    }

    private companion object {
        const val TIMEOUT = 30_000L
        const val SETTLE_MS = 600L

        /** Half of one CameraX retry cycle while the camera is held, as the tests fake it. */
        const val RETRY_MS = 300L
    }
}
