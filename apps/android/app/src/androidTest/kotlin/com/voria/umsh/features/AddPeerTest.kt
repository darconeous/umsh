package com.voria.umsh.features

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.Destination
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.LocalAppCoreHost
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.ShellState
import com.voria.umsh.app.Tags
import com.voria.umsh.app.TestWindows
import com.voria.umsh.app.UmshKey
import com.voria.umsh.app.UmshShell
import com.voria.umsh.app.rememberShellState
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.core.nodeUriForAddress
import com.voria.umsh.designsystem.AddressGrouping
import com.voria.umsh.designsystem.LocalWindowOverride
import com.voria.umsh.designsystem.UmshTheme
import com.voria.umsh.features.peers.AddPeerViewModel
import com.voria.umsh.features.peers.ImportPreviewSheet
import com.voria.umsh.features.peers.ImportSave
import com.voria.umsh.features.peers.PeerImportHost
import com.voria.umsh.models.PeerSummary
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * Add peer and the import preview (`add-peer.svg` 1–4) over the staging
 * core, from both ways in: the Peers list's Add peer, and Conversations'
 * New chat › New message (D11).
 */
class AddPeerTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private lateinit var shell: ShellState

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

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

    private fun show(runtime: AppRuntime, setContent: (@Composable () -> Unit) -> Unit = compose::setContent) {
        setContent {
            UmshTheme(fallbackScheme = true) {
                CompositionLocalProvider(
                    LocalAppRuntime provides runtime,
                    LocalAppCoreHost provides fresh.host,
                    LocalWindowOverride provides TestWindows.Phone,
                ) {
                    val state = rememberShellState()
                    shell = state
                    UmshShell(state)
                }
            }
        }
        waitForTag(Tags.CONVERSATIONS_ROOT)
    }

    // Unmerged: the field's line is merged into the field itself.
    private fun present(tag: String) = compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()

    private fun waitForTag(tag: String) = compose.waitUntil(TIMEOUT) { present(tag) }

    private fun waitGone(tag: String) = compose.waitUntil(TIMEOUT) { !present(tag) }

    private fun text(tag: String): String = compose.onNodeWithTag(tag, useUnmergedTree = true).fetchSemanticsNode().config
        .getOrNull(SemanticsProperties.Text)?.joinToString("") { it.text }.orEmpty()

    private fun string(id: Int) = context.getString(id)

    /** Peers › Add peer. */
    private fun openFromPeers() {
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitForTag(Tags.PEERS_ADD)
        compose.onNodeWithTag(Tags.PEERS_ADD).performClick()
        waitForTag(Tags.ADD_PEER)
    }

    /** Conversations › New chat › New message. */
    private fun openFromConversations() {
        waitForTag(Tags.CONVERSATIONS_NEW_CHAT)
        compose.onNodeWithTag(Tags.CONVERSATIONS_NEW_CHAT).performClick()
        waitForTag(Tags.NEW_CHAT_MESSAGE)
        compose.onNodeWithTag(Tags.NEW_CHAT_MESSAGE).performClick()
        waitForTag(Tags.ADD_PEER)
    }

    private fun enter(input: String) {
        compose.onNodeWithTag(Tags.ADD_PEER_FIELD).performTextReplacement(input)
        compose.onNodeWithTag(Tags.ADD_PEER_PREVIEW).performClick()
    }

    private fun closeSheet() {
        compose.waitForIdle()
        InstrumentationRegistry.getInstrumentation().sendKeyDownUpSync(android.view.KeyEvent.KEYCODE_BACK)
        waitGone(Tags.IMPORT_SHEET)
    }

    // --- Ways in -----------------------------------------------------------

    @Test
    fun newMessageOpensAddPeerOnConversations() {
        show(runtime())
        openFromConversations()
        assertEquals(Destination.Conversations, shell.selected)
        assertEquals(UmshKey.AddPeer(Destination.Conversations), shell.stacks.getValue(Destination.Conversations).last())
        compose.onNodeWithTag(Tags.NEW_CHAT_SHEET).assertDoesNotExist()
        // Back returns to the list.
        compose.onNodeWithTag(Tags.TOP_BAR_BACK).performClick()
        waitForTag(Tags.CONVERSATION_LIST)
        assertEquals(listOf(UmshKey.ConversationsRoot), shell.stacks.getValue(Destination.Conversations).toList())
    }

    @Test
    fun theListsButtonOpensAddPeerOnPeers() {
        show(runtime())
        openFromPeers()
        assertEquals(UmshKey.AddPeer(Destination.Peers), shell.stacks.getValue(Destination.Peers).last())
        compose.onNodeWithTag(Tags.ADD_PEER_PREVIEW).assertIsNotEnabled()
        // Show your code: Your identity's QR sheet, over Add peer.
        compose.onNodeWithTag(Tags.ADD_PEER_SHOW_CODE).performClick()
        waitForTag(Tags.QR_IMAGE)
        compose.waitUntil(TIMEOUT) { compose.onAllNodesWithTag(Tags.QR_COPY_LINK).fetchSemanticsNodes().any { SemanticsActions.OnClick in it.config && SemanticsProperties.Disabled !in it.config } }
    }

    /** Board 2: the empty list's New message is the same way in. */
    @Test
    fun theEmptyListsNewMessage() {
        val runtime = runtime()
        runBlocking {
            for (address in runtime.appState.value!!.conversations.map { it.address }) runtime.deleteConversation(address).await()
        }
        show(runtime)
        waitForTag(Tags.CONVERSATIONS_EMPTY)
        compose.onNodeWithTag(Tags.CONVERSATIONS_NEW_CHAT).assertDoesNotExist()
        compose.onNodeWithTag(Tags.CONVERSATIONS_EMPTY_NEW_MESSAGE).performClick()
        waitForTag(Tags.ADD_PEER)
        assertEquals(UmshKey.AddPeer(Destination.Conversations), shell.stacks.getValue(Destination.Conversations).last())
    }

    // --- The field ---------------------------------------------------------

    @Test
    fun eachInputKind() {
        show(runtime())
        openFromPeers()
        val other = ImportFixtures.address(0x41)

        // Board 2: not a node; editing clears the line.
        enter("umsh:x:Mx4eTq8VbN3k")
        waitForTag(Tags.ADD_PEER_PROBLEM)
        assertEquals(string(R.string.add_peer_not_peer), text(Tags.ADD_PEER_PROBLEM))
        compose.onNodeWithTag(Tags.IMPORT_SHEET).assertDoesNotExist()
        compose.onNodeWithTag(Tags.ADD_PEER_FIELD).performTextReplacement("umsh:x:Mx4eTq8VbN3")
        waitGone(Tags.ADD_PEER_PROBLEM)
        // A channel link opens the channel's join preview over Add peer (`qr-scanner.svg` 4); Back dismisses it.
        enter("umsh:gs:hike-club")
        waitForTag(Tags.CHANNEL_SHEET)
        compose.waitUntil(TIMEOUT) { present(Tags.CHANNEL_PREVIEW_NAME) && text(Tags.CHANNEL_PREVIEW_NAME) == "hike-club" }
        compose.onNodeWithTag(Tags.ADD_PEER_PROBLEM).assertDoesNotExist()
        compose.waitForIdle()
        InstrumentationRegistry.getInstrumentation().sendKeyDownUpSync(android.view.KeyEvent.KEYCODE_BACK)
        waitGone(Tags.CHANNEL_SHEET)
        compose.onNodeWithTag(Tags.ADD_PEER).assertIsDisplayed()

        // A bare link, the address, and the hex key each preview the key alone.
        for (input in listOf(nodeUriForAddress(other), other, ImportFixtures.hex(other))) {
            enter(input)
            waitForTag(Tags.IMPORT_SHEET)
            compose.onNodeWithTag(Tags.IMPORT_HEADER).assert(hasMergedText(string(R.string.import_caption_key_only)))
            compose.onNodeWithTag(Tags.IMPORT_ROLE).assertDoesNotExist()
            compose.onNodeWithTag(Tags.IMPORT_SIGNATURE).assertDoesNotExist()
            closeSheet()
        }
        // Nothing was stored by previewing.
        assertNull(currentRuntime().appState.value!!.peers.firstOrNull { it.address == other })
    }

    @Test
    fun eachSignatureState() {
        show(runtime())
        openFromPeers()
        // Signed and valid: the details, the claims note, and no warning.
        enter(ImportFixtures.signedLink(0x42).link)
        waitForTag(Tags.IMPORT_SHEET)
        compose.onNodeWithTag(Tags.IMPORT_HEADER).assert(hasMergedText("Marmot"))
        compose.onNodeWithTag(Tags.IMPORT_HEADER).assert(hasMergedText(string(R.string.import_caption_details)))
        compose.onNodeWithTag(Tags.IMPORT_ROLE).assert(hasMergedText(string(R.string.role_chat)))
        compose.onNodeWithTag(Tags.IMPORT_CAPABILITIES).assertIsDisplayed()
        compose.onNodeWithTag(Tags.IMPORT_LOCATION).assert(hasMergedText("44.05"))
        compose.onNodeWithTag(Tags.IMPORT_REPORTED).assertExists()
        compose.onNodeWithTag(Tags.IMPORT_CLAIMS).assertExists()
        compose.onNodeWithTag(Tags.IMPORT_SIGNATURE).assertDoesNotExist()
        closeSheet()

        enter(ImportFixtures.unsignedLink(0x43))
        waitForTag(Tags.IMPORT_SIGNATURE)
        compose.onNodeWithTag(Tags.IMPORT_SIGNATURE).assert(hasMergedText(string(R.string.identity_unsigned_warning)))
        closeSheet()

        enter(ImportFixtures.tamperedLink(0x49))
        waitForTag(Tags.IMPORT_SIGNATURE)
        compose.onNodeWithTag(Tags.IMPORT_SIGNATURE).assert(hasMergedText(string(R.string.identity_invalid_warning)))
        closeSheet()

        // Details that cannot be read: the key alone.
        enter(ImportFixtures.unreadableLink(0x45))
        waitForTag(Tags.IMPORT_SHEET)
        compose.onNodeWithTag(Tags.IMPORT_HEADER).assert(hasMergedText(string(R.string.import_caption_key_only)))
        compose.onNodeWithTag(Tags.IMPORT_ROLE).assertDoesNotExist()
    }

    // --- Leaving -------------------------------------------------------------

    @Test
    fun savePeerOpensItsPageInAddPeersPlace() {
        val runtime = runtime()
        show(runtime)
        openFromPeers()
        val signed = ImportFixtures.signedLink(0x46)
        enter(signed.link)
        waitForTag(Tags.IMPORT_SHEET)
        compose.onNodeWithTag(Tags.IMPORT_NAME).performScrollTo().performTextReplacement("Ridge marmot")
        compose.onNodeWithTag(Tags.IMPORT_SAVE).performScrollTo().performClick()
        waitForTag(Tags.PEER_PAGE)
        waitGone(Tags.IMPORT_SHEET)
        assertEquals(
            listOf(UmshKey.PeersRoot, UmshKey.PeerPage(signed.address, Destination.Peers)),
            shell.stacks.getValue(Destination.Peers).toList(),
        )
        val saved = runtime.appState.value!!.peers.first { it.address == signed.address }
        assertTrue(saved.isSaved)
        assertEquals("Ridge marmot", saved.alias)
        assertEquals("Marmot", saved.advertisedName)
        assertFalse(runtime.appState.value!!.directConversations.any { it.peer.address == signed.address })
    }

    @Test
    fun messageOpensTheConversationOnConversations() {
        val runtime = runtime()
        show(runtime)
        openFromConversations()
        val other = ImportFixtures.address(0x47)
        enter(other)
        waitForTag(Tags.IMPORT_SHEET)
        compose.onNodeWithTag(Tags.IMPORT_MESSAGE).performScrollTo().performClick()
        compose.waitUntil(TIMEOUT) { shell.stacks.getValue(Destination.Conversations).lastOrNull() == UmshKey.Thread(other) }
        assertEquals(listOf(UmshKey.ConversationsRoot, UmshKey.Thread(other)), shell.stacks.getValue(Destination.Conversations).toList())
        assertTrue(runtime.appState.value!!.peers.first { it.address == other }.isSaved)
        assertTrue(runtime.appState.value!!.directConversations.any { it.peer.address == other })
    }

    @Test
    fun aSavedNodesCodeOpensItsPage() {
        val runtime = runtime()
        show(runtime)
        val saved = runtime.appState.value!!.peers.first { it.isSaved && !it.isCompanionRadio }
        openFromConversations()
        enter(nodeUriForAddress(saved.address))
        waitForTag(Tags.PEER_PAGE)
        compose.onNodeWithTag(Tags.IMPORT_SHEET).assertDoesNotExist()
        assertEquals(
            listOf(UmshKey.ConversationsRoot, UmshKey.PeerPage(saved.address, Destination.Conversations)),
            shell.stacks.getValue(Destination.Conversations).toList(),
        )
    }

    @Test
    fun thisPhonesOwnAddressOpensYourIdentity() {
        val runtime = runtime()
        show(runtime)
        openFromPeers()
        enter(runtime.identity.value.address)
        waitForTag(Tags.YOUR_IDENTITY)
        assertEquals(Destination.Settings, shell.selected)
        assertEquals(listOf(UmshKey.PeersRoot), shell.stacks.getValue(Destination.Peers).toList())
    }

    // --- TalkBack (§3.10) ------------------------------------------------------

    @Test
    fun whatTalkBackReads() {
        show(runtime())
        // The FAB and the sheet's item speak their text.
        compose.onNodeWithTag(Tags.CONVERSATIONS_NEW_CHAT).assert(hasMergedText(string(R.string.new_chat)))
        openFromConversations()
        // The field names what it takes, and its line is read as an error.
        compose.onNodeWithTag(Tags.ADD_PEER_FIELD).assert(hasMergedText(string(R.string.add_peer_field)))
        enter("not a key")
        waitForTag(Tags.ADD_PEER_PROBLEM)
        compose.onNodeWithTag(Tags.ADD_PEER_FIELD).assert(SemanticsMatcher.keyIsDefined(SemanticsProperties.Error))
        compose.onNodeWithTag(Tags.ADD_PEER_PROBLEM, useUnmergedTree = true).assert(SemanticsMatcher.keyIsDefined(SemanticsProperties.LiveRegion))
        compose.onNodeWithTag(Tags.ADD_PEER_SHOW_CODE)
            .assert(SemanticsMatcher.expectValue(SemanticsProperties.Role, androidx.compose.ui.semantics.Role.Button))

        enter(ImportFixtures.unsignedLink(0x48))
        waitForTag(Tags.IMPORT_SHEET)
        // The header is one heading; each detail row and the warning one stop.
        compose.onNodeWithTag(Tags.IMPORT_HEADER).assert(SemanticsMatcher.keyIsDefined(SemanticsProperties.Heading))
        for (tag in listOf(Tags.IMPORT_ADDRESS, Tags.IMPORT_ROLE, Tags.IMPORT_LOCATION, Tags.IMPORT_REPORTED, Tags.IMPORT_SIGNATURE)) {
            assertTrue(tag, compose.onNodeWithTag(tag).fetchSemanticsNode().config.isMergingSemanticsOfDescendants)
        }
        // "Address" and the address are one stop, and the row copies it.
        val address = ImportFixtures.address(0x48)
        compose.onNodeWithTag(Tags.IMPORT_ADDRESS)
            .assert(hasMergedText(string(R.string.import_address)))
            .assert(hasMergedText(AddressGrouping.grouped(address)))
            .assert(SemanticsMatcher.keyIsDefined(SemanticsActions.OnClick))
        assertEquals(1, compose.onAllNodes(hasMergedText(AddressGrouping.grouped(address))).fetchSemanticsNodes().size)
        compose.onNodeWithTag(Tags.IMPORT_NAME).assert(hasMergedText(string(R.string.import_name)))
        compose.onNodeWithTag(Tags.IMPORT_SAVE).assertIsEnabled()
        compose.onNodeWithTag(Tags.IMPORT_MESSAGE).assertIsEnabled()
    }

    /** While a save runs its button keeps its name and reads as saving; the other waits too. */
    @Test
    fun aBusyButtonKeepsItsName() {
        val runtime = runtime()
        val pending = CompletableDeferred<String>()
        val host = object : PeerImportHost {
            override val ownAddress = runtime.identity.value.address

            override fun stored(address: String): PeerSummary? = null

            override fun save(input: String, alias: String?, startConversation: Boolean): Deferred<String> = pending
        }
        val viewModel = AddPeerViewModel(host)
        compose.runOnUiThread { viewModel.preview(ImportFixtures.signedLink(0x49).link) }
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                CompositionLocalProvider(LocalAppRuntime provides runtime, LocalWindowOverride provides TestWindows.Phone) {
                    viewModel.preview.collectAsStateWithLifecycle().value?.let { ImportPreviewSheet(it, viewModel) }
                }
            }
        }
        waitForTag(Tags.IMPORT_SHEET)
        compose.onNodeWithTag(Tags.IMPORT_SAVE).performScrollTo().performClick()
        compose.waitUntil(TIMEOUT) { viewModel.save.value is ImportSave.Saving }
        compose.onNodeWithTag(Tags.IMPORT_SAVE)
            .assert(hasMergedText(string(R.string.import_save)))
            .assert(SemanticsMatcher.expectValue(SemanticsProperties.StateDescription, string(R.string.import_saving)))
            .assertIsNotEnabled()
        compose.onNodeWithTag(Tags.IMPORT_MESSAGE)
            .assert(hasMergedText(string(R.string.import_message)))
            .assert(SemanticsMatcher.keyNotDefined(SemanticsProperties.StateDescription))
            .assertIsNotEnabled()
        pending.cancel()
    }

    /** New chat's sheet stays open across a configuration change, as on a rotation. */
    @Test
    fun newChatSurvivesRecreation() {
        val runtime = runtime()
        // Drawn by the activity itself, so the recreated activity draws it again.
        val drawn: (@Composable () -> Unit) -> Unit = { content ->
            compose.activityRule.scenario.onActivity { it.setContent(content = content) }
        }
        show(runtime, drawn)
        compose.onNodeWithTag(Tags.CONVERSATIONS_NEW_CHAT).performClick()
        waitForTag(Tags.NEW_CHAT_MESSAGE)
        compose.activityRule.scenario.recreate()
        show(runtime, drawn)
        waitForTag(Tags.NEW_CHAT_MESSAGE)
    }

    private fun currentRuntime(): AppRuntime = (fresh.host.state.value as HostState.Ready).runtime

    private fun hasMergedText(part: String) = SemanticsMatcher("text contains \"$part\"") { node ->
        val texts = node.config.getOrNull(SemanticsProperties.Text).orEmpty().map { it.text } +
            node.config.getOrNull(SemanticsProperties.EditableText)?.text.orEmpty() +
            node.config.getOrNull(SemanticsProperties.ContentDescription).orEmpty()
        texts.any { it.contains(part) }
    }

    private companion object {
        const val TIMEOUT = 30_000L
    }
}
