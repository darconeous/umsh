package com.voria.umsh.features

import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.LinkAnnotation
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.app.AppRoot
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.Destination
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.LinkOrigin
import com.voria.umsh.app.LocalAppCoreHost
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.LocalOpenRequests
import com.voria.umsh.app.OpenRequest
import com.voria.umsh.app.OpenRequests
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
import com.voria.umsh.services.preferences.OnboardingStep
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * Opened `umsh:` links (product-structure, "Deep links"; `peer-page.svg` 5)
 * over the staging core: a node's page above whatever shows, with Close; this
 * phone's own link; a bad or channel link in the import sheet; a link that
 * waits out onboarding; and a link in a message, by the same route. Links
 * from another app, through the activity, are [LinkActivityTest]'s.
 */
class LinkTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private lateinit var shell: ShellState
    private val requests = OpenRequests()
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun runtime(): AppRuntime = runBlocking {
        fresh.host.preferences.setFallbackScheme(true)
        fresh.host.preferences.setNotificationsAsked()
        fresh.host.ensureRuntime(staging = true)
        val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
        val runtime = ready.runtime
        withTimeout(TIMEOUT) { runtime.lifecycle.first { it is MobileAppLifecycle.Running } }
        runtime.setOnboarding(OnboardingStep.Done).await()
        withTimeout(TIMEOUT) { runtime.appState.first { state -> state?.peers?.any { it.advertisedName == "Maya Ortiz" } == true } }
        runtime
    }

    private fun show(runtime: AppRuntime) {
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                CompositionLocalProvider(
                    LocalAppRuntime provides runtime,
                    LocalAppCoreHost provides fresh.host,
                    LocalWindowOverride provides TestWindows.Phone,
                    LocalOpenRequests provides requests,
                ) {
                    val state = rememberShellState()
                    shell = state
                    UmshShell(state)
                }
            }
        }
        compose.onNodeWithTag(Tags.CONVERSATIONS_ROOT).assertIsDisplayed()
    }

    private fun open(link: String, origin: LinkOrigin = LinkOrigin.InApp) = requests.offer(OpenRequest.Link(link, origin))

    private fun present(tag: String) = compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()

    private fun waitFor(condition: () -> Boolean) = compose.waitUntil(TIMEOUT, condition)

    private fun waitForTag(tag: String) = waitFor { present(tag) }

    private fun waitGone(tag: String) = waitFor { !present(tag) }

    private fun text(id: Int) = context.getString(id)

    private fun back() = InstrumentationRegistry.getInstrumentation().sendKeyDownUpSync(android.view.KeyEvent.KEYCODE_BACK)

    private fun textOf(node: SemanticsNodeInteraction): String =
        node.fetchSemanticsNode().config.getOrNull(SemanticsProperties.Text)?.joinToString("") { it.text }.orEmpty()

    private fun hasTextIn(tag: String, wanted: String): Boolean =
        compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().any { node ->
            node.config.getOrNull(SemanticsProperties.Text)?.any { it.text.contains(wanted) } == true ||
                node.config.getOrNull(SemanticsProperties.EditableText)?.text?.contains(wanted) == true
        }

    /** `peer-page.svg` 5: an unknown node's link opens its page above whatever showed, unsaved, with Close back there. */
    @Test
    fun aNodesLinkOpensItsPageAboveTheShellAndCloseReturns() {
        val runtime = runtime()
        show(runtime)
        // On another screen: Settings, at Your identity.
        compose.onAllNodesWithTag(Tags.NAV_SETTINGS)[0].performClick()
        compose.onNodeWithTag(Tags.SETTINGS_YOUR_IDENTITY).performClick()
        waitForTag(Tags.YOUR_IDENTITY)

        val marmot = ImportFixtures.signedLink(0x62)
        open(marmot.link)
        waitForTag(Tags.PEER_PAGE)
        assertEquals(listOf(UmshKey.Shell, UmshKey.PeerPage(marmot.address, null, LinkOrigin.InApp)), shell.appStack.toList())
        // Above the shell: no navigation bar, and Close, not Back.
        assertFalse(present(Tags.SHELL))
        assertFalse(present(Tags.TOP_BAR_BACK))
        assertTrue(hasTextIn(Tags.PEER_NAME, "Marmot"))
        assertTrue(present(Tags.PEER_ADD))
        compose.onNodeWithTag(Tags.PEER_ADVERTISED, useUnmergedTree = true).performScrollTo()
        assertTrue(hasTextIn(Tags.PEER_ADVERTISED, text(R.string.peer_advertised_imported)))
        // Recorded, unsaved: nothing is saved until Add to Peers.
        val stored = runtime.appState.value!!.peers.first { it.address == marmot.address }
        assertFalse(stored.isSaved)
        assertTrue(requests.pending.value.isEmpty())

        compose.onNodeWithTag(Tags.TOP_BAR_CLOSE).performClick()
        waitForTag(Tags.YOUR_IDENTITY)
        assertEquals(Destination.Settings, shell.selected)
        assertEquals(listOf(UmshKey.Shell), shell.appStack.toList())
    }

    /** Two links, two pages, each its own; Back from the second shows the first; Message leaves for Conversations. */
    @Test
    fun twoLinksOpenTwoPagesAndMessageLeavesForConversations() {
        val runtime = runtime()
        show(runtime)
        val first = ImportFixtures.signedLink(0x63, name = "Marmot")
        val second = ImportFixtures.signedLink(0x64, name = "Pika")
        open(first.link)
        waitFor { hasTextIn(Tags.PEER_NAME, "Marmot") }
        open(second.link)
        waitFor { hasTextIn(Tags.PEER_NAME, "Pika") }
        assertEquals(3, shell.appStack.size)
        back()
        waitFor { hasTextIn(Tags.PEER_NAME, "Marmot") }
        assertEquals(2, shell.appStack.size)

        compose.onNodeWithTag(Tags.PEER_VERB_MESSAGE).performClick()
        waitForTag(Tags.THREAD)
        assertEquals(listOf(UmshKey.Shell), shell.appStack.toList())
        assertEquals(Destination.Conversations, shell.selected)
        assertEquals(UmshKey.Thread(first.address), shell.stacks.getValue(Destination.Conversations).last())
    }

    /** A saved node's link opens its page as it is, with nothing to add. */
    @Test
    fun aSavedNodesLinkOpensItsPage() {
        val runtime = runtime()
        show(runtime)
        val maya = runtime.appState.value!!.peers.first { it.advertisedName == "Maya Ortiz" }
        open(nodeUriForAddress(maya.address))
        waitForTag(Tags.PEER_PAGE)
        assertTrue(hasTextIn(Tags.PEER_NAME, "Maya Ortiz"))
        assertFalse(present(Tags.PEER_ADD))
        assertTrue(present(Tags.TOP_BAR_CLOSE))
    }

    /** "Deep links" 2.2: this phone's own link selects Settings at Your identity. */
    @Test
    fun ownLinkOpensYourIdentity() {
        val runtime = runtime()
        show(runtime)
        open(nodeUriForAddress(runtime.identity.value.address))
        waitForTag(Tags.YOUR_IDENTITY)
        assertEquals(Destination.Settings, shell.selected)
        assertFalse(present(Tags.PEER_PAGE))
        assertEquals(listOf(UmshKey.Shell), shell.appStack.toList())
    }

    /** "Deep links" 2.1: a link that names no node opens the import sheet with what is wrong; corrected, it previews. */
    @Test
    fun aBadLinkOpensTheImportSheetWithItsReason() {
        val runtime = runtime()
        show(runtime)
        open("umsh:x:Mx4eTq8VbN3k")
        waitForTag(Tags.LINK_IMPORT_SHEET)
        assertTrue(hasTextIn(Tags.ADD_PEER_FIELD, "umsh:x:Mx4eTq8VbN3k"))
        assertTrue(hasTextIn(Tags.ADD_PEER_PROBLEM, text(R.string.add_peer_not_peer)))
        assertFalse(present(Tags.PEER_PAGE))

        // Corrected in the field: the import preview proper, and Save peer opens the page above the shell.
        val pika = ImportFixtures.signedLink(0x65, name = "Pika")
        compose.onNodeWithTag(Tags.ADD_PEER_FIELD).performTextReplacement(pika.link)
        compose.onNodeWithTag(Tags.ADD_PEER_PREVIEW).performClick()
        waitForTag(Tags.IMPORT_SHEET)
        compose.onNodeWithTag(Tags.IMPORT_SAVE).performScrollTo().performClick()
        waitForTag(Tags.PEER_PAGE)
        waitGone(Tags.IMPORT_SHEET)
        assertFalse(present(Tags.LINK_IMPORT_SHEET))
        assertTrue(hasTextIn(Tags.PEER_NAME, "Pika"))
        assertTrue(runtime.appState.value!!.peers.first { it.address == pika.address }.isSaved)
        assertTrue(present(Tags.TOP_BAR_CLOSE))
    }

    /** The same bad link opened again starts the sheet over: the link and its reason, not what was edited or previewed. */
    @Test
    fun theSameBadLinkOpenedAgainStartsTheSheetOver() {
        val runtime = runtime()
        show(runtime)
        open("umsh:x:Mx4eTq8VbN3k")
        waitForTag(Tags.LINK_IMPORT_SHEET)
        val pika = ImportFixtures.signedLink(0x66, name = "Pika")
        compose.onNodeWithTag(Tags.ADD_PEER_FIELD).performTextReplacement(pika.link)
        compose.onNodeWithTag(Tags.ADD_PEER_PREVIEW).performClick()
        waitForTag(Tags.IMPORT_SHEET)

        open("umsh:x:Mx4eTq8VbN3k")
        waitGone(Tags.IMPORT_SHEET)
        waitForTag(Tags.LINK_IMPORT_SHEET)
        waitFor { hasTextIn(Tags.ADD_PEER_FIELD, "umsh:x:Mx4eTq8VbN3k") }
        waitFor { hasTextIn(Tags.ADD_PEER_PROBLEM, text(R.string.add_peer_not_peer)) }
    }

    /**
     * A channel link (product-structure, "Deep links" 1): Settings selected
     * at Channels, and Join channel over it with the link looked up; Close
     * returns to Channels, nothing joined. The same link opened again over
     * a page whose field was edited starts it over, looked up again.
     */
    @Test
    fun aChannelLinkOpensJoinChannelOverSettings() {
        val runtime = runtime()
        show(runtime)
        open("umsh:gs:hike-club")
        waitForTag(Tags.CHANNEL_JOIN)
        waitFor { hasTextIn(Tags.CHANNEL_PREVIEW_NAME, "hike-club") }
        compose.onNodeWithTag(Tags.LINK_IMPORT_SHEET).assertDoesNotExist()
        assertEquals(Destination.Settings, shell.selected)
        assertEquals(UmshKey.Channels, shell.stacks.getValue(Destination.Settings).last())

        compose.onNodeWithTag(Tags.CHANNEL_JOIN_FIELD).performTextReplacement("umsh:gs:edited")
        waitGone(Tags.CHANNEL_PREVIEW)
        open("umsh:gs:hike-club")
        waitFor { hasTextIn(Tags.CHANNEL_PREVIEW_NAME, "hike-club") }
        assertTrue(hasTextIn(Tags.CHANNEL_JOIN_FIELD, "umsh:gs:hike-club"))
        assertEquals(1, shell.appStack.count { it is UmshKey.ChannelJoin })
        compose.onNodeWithTag(Tags.DIALOG_CLOSE).performClick()
        waitGone(Tags.CHANNEL_JOIN)
        waitForTag(Tags.CHANNELS)
        assertTrue(runtime.appState.value!!.channels.none { it.canonicalName == "hike-club" })
    }

    /** A link opened during onboarding waits until it is done, then opens. */
    @Test
    fun aLinkWaitsOutOnboarding() {
        val runtime = runtime()
        // Staging starts onboarded: back to Welcome, as a first launch is.
        runBlocking { runtime.setOnboarding(OnboardingStep.Welcome).await() }
        compose.setContent { AppRoot(fresh.host, requests) }
        waitForTag(Tags.ONBOARDING)
        val marmot = ImportFixtures.signedLink(0x69)
        open(marmot.link, LinkOrigin.OtherApp)
        compose.waitForIdle()
        Thread.sleep(SETTLE_MS)
        assertFalse(present(Tags.PEER_PAGE))
        assertEquals(1, requests.pending.value.size)

        runBlocking { runtime.setOnboarding(OnboardingStep.Done).await() }
        waitForTag(Tags.PEER_PAGE)
        waitFor { hasTextIn(Tags.PEER_NAME, "Marmot") }
        assertTrue(requests.pending.value.isEmpty())
    }

    /** A link in a staged message opens the same page, and Close returns to the thread. TalkBack reaches the link. */
    @Test
    fun aLinkInAMessageOpensTheSamePage() {
        val runtime = runtime()
        val maya = runtime.appState.value!!.peers.first { it.advertisedName == "Maya Ortiz" }
        val marmot = ImportFixtures.signedLink(0x67)
        val conversation = runBlocking { runtime.startConversation(maya.address).await() }
        val body = "Meet ${marmot.link} at the trailhead."
        runBlocking { runtime.send(conversation, body, null).await() }
        show(runtime)
        compose.runOnUiThread { shell.openConversation(conversation) }
        waitForTag(Tags.THREAD)
        waitFor { bodyNode(body) != null }

        // The link is its own annotation in the body, so TalkBack lists it among the message's links.
        val shown = checkNotNull(bodyNode(body))
        val annotated: AnnotatedString = shown.config.getOrNull(SemanticsProperties.Text)!!.first { it.text == body }
        val links = annotated.getLinkAnnotations(0, annotated.length)
        assertEquals(1, links.size)
        val link = links.single().item as LinkAnnotation.Clickable
        assertEquals(marmot.link, link.tag)

        // Tapped: the link's listener runs as a tap on it does.
        compose.runOnUiThread { link.linkInteractionListener!!.onClick(link) }
        waitForTag(Tags.PEER_PAGE)
        assertEquals(UmshKey.PeerPage(marmot.address, null, LinkOrigin.InApp), shell.appStack.last())
        assertTrue(hasTextIn(Tags.PEER_NAME, "Marmot"))
        compose.onNodeWithTag(Tags.TOP_BAR_CLOSE).performClick()
        waitForTag(Tags.THREAD)

        // Back on the page does the same.
        compose.runOnUiThread { link.linkInteractionListener!!.onClick(link) }
        waitForTag(Tags.PEER_PAGE)
        back()
        waitForTag(Tags.THREAD)
        assertEquals(listOf(UmshKey.Shell), shell.appStack.toList())
    }

    /** §3.10: Close is named Close, and the page's name heads it. */
    @Test
    fun whatTalkBackReads() {
        val runtime = runtime()
        show(runtime)
        open(ImportFixtures.signedLink(0x68).link)
        waitForTag(Tags.TOP_BAR_CLOSE)
        val close = compose.onNodeWithTag(Tags.TOP_BAR_CLOSE).fetchSemanticsNode()
        val description = close.config.getOrNull(SemanticsProperties.ContentDescription)
            ?: close.children.firstNotNullOfOrNull { it.config.getOrNull(SemanticsProperties.ContentDescription) }
        assertEquals(listOf(text(R.string.action_close)), description)
        assertNotNull(close.config.getOrNull(androidx.compose.ui.semantics.SemanticsActions.OnClick))
        assertTrue(textOf(compose.onNodeWithTag(Tags.PEER_NAME, useUnmergedTree = true)).contains("Marmot"))
    }

    private fun bodyNode(body: String) =
        compose.onAllNodesWithTag(Tags.BUBBLE, useUnmergedTree = true).fetchSemanticsNodes()
            .flatMap { listOf(it) + it.children }
            .firstOrNull { node -> node.config.getOrNull(SemanticsProperties.Text)?.any { it.text == body } == true }

    private companion object {
        const val TIMEOUT = 30_000L
        const val SETTLE_MS = 1_500L
    }
}
