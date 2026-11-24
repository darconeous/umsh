package com.voria.umsh.app

import com.voria.umsh.core.MobileAppException
import com.voria.umsh.features.peers.ImportFixtures
import com.voria.umsh.models.AppStateSnapshot
import com.voria.umsh.models.PeerSummary
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** The peer page's and list's commands over the real core and the staged mesh. */
class AppRuntimePeersTest {
    @get:Rule val temp = TemporaryFolder()

    private lateinit var staged: StagedHost

    @After
    fun tearDown() = runBlocking { staged.close() }

    private suspend fun start(): AppRuntime {
        staged = StagedHost(temp.newFolder())
        val runtime = staged.start()
        staged.stateWhere { state -> state.peers.any { it.advertisedName == "Glen Alpine Relay" } }
        return runtime
    }

    private fun AppStateSnapshot.named(name: String): PeerSummary? = peers.firstOrNull { it.advertisedName == name }

    private fun AppStateSnapshot.address(name: String): String = named(name)!!.address

    /*
     * Any hearing of a node disarms its watch, and the staged repeaters
     * advertise as the air stands up, so a watch armed on one could be
     * disarmed between the arm and its reload. These tests watch nodes that
     * stay silent unless asked: Jules Whitaker (saved) and Sam Ihara (not).
     */

    @Test
    fun editsShowInTheListsAtOnce() = runBlocking<Unit> {
        val runtime = start()
        val jules = runtime.appState.value!!.address("Jules Whitaker")

        runtime.setAlias(jules, "  Base camp  ").await()
        assertEquals("Base camp", runtime.appState.value!!.named("Jules Whitaker")!!.alias)
        // Empty falls back to the advertised name.
        runtime.setAlias(jules, " ").await()
        assertNull(runtime.appState.value!!.named("Jules Whitaker")!!.alias)

        runtime.setFavorite(jules, true).await()
        assertTrue(runtime.appState.value!!.named("Jules Whitaker")!!.isFavorite)

        runtime.setNotifyWhenHeard(jules, true).await()
        assertTrue(runtime.appState.value!!.named("Jules Whitaker")!!.notifyWhenHeard)
        runtime.setNotifyWhenHeard(jules, false).await()
        assertFalse(runtime.appState.value!!.named("Jules Whitaker")!!.notifyWhenHeard)
    }

    @Test
    fun promotingSavesAndDemotingDropsTheFavoriteAndAlias() = runBlocking<Unit> {
        val runtime = start()
        val sam = runtime.appState.value!!.address("Sam Ihara")
        assertFalse(runtime.appState.value!!.named("Sam Ihara")!!.isSaved)
        // A node heard only over the air, not yet on Peers, can still be watched.
        runtime.setNotifyWhenHeard(sam, true).await()
        assertTrue(runtime.appState.value!!.named("Sam Ihara")!!.notifyWhenHeard)

        runtime.promotePeer(sam).await()
        runtime.setFavorite(sam, true).await()
        runtime.setAlias(sam, "Sam").await()
        val saved = runtime.appState.value!!.named("Sam Ihara")!!
        assertTrue(saved.isSaved && saved.isFavorite)

        runtime.demotePeer(sam).await()
        val demoted = runtime.appState.value!!.named("Sam Ihara")!!
        assertFalse(demoted.isSaved)
        assertFalse(demoted.isFavorite)
        assertNull(demoted.alias)
    }

    @Test
    fun deletingOneAConversationHoldsNeedsTheConversationToo() = runBlocking<Unit> {
        val runtime = start()
        val state = staged.stateWhere { it.directConversations.any { conversation -> conversation.peer.advertisedName == "Maya Ortiz" } }
        val maya = state.address("Maya Ortiz")
        try {
            runtime.deletePeer(maya, withConversation = false).await()
            fail("deleted a peer a conversation holds")
        } catch (_: MobileAppException.InvalidRequest) {
            // The core refuses; nothing changed.
        }
        assertNotNull(runtime.appState.value!!.named("Maya Ortiz"))

        runtime.deletePeer(maya, withConversation = true).await()
        val after = runtime.appState.value!!
        assertNull(after.named("Maya Ortiz"))
        assertTrue(after.directConversations.none { it.peer.address == maya })
    }

    @Test
    fun deletingOneWithNoConversation() = runBlocking<Unit> {
        val runtime = start()
        val state = runtime.appState.value!!
        val tallac = state.address("Tallac Ridge")
        assertTrue(state.directConversations.none { it.peer.address == tallac })
        runtime.deletePeer(tallac, withConversation = false).await()
        assertNull(runtime.appState.value!!.named("Tallac Ridge"))
    }

    @Test
    fun clearingMessagesKeepsTheConversation() = runBlocking<Unit> {
        val runtime = start()
        val state = staged.stateWhere { it.directConversations.any { conversation -> conversation.peer.advertisedName == "Maya Ortiz" } }
        val maya = state.address("Maya Ortiz")
        assertTrue(runtime.messageCount(maya) > 0)

        runtime.setConversationNotifications(maya, false).await()
        assertFalse(runtime.appState.value!!.directConversations.first { it.peer.address == maya }.notificationsEnabled)

        runtime.clearMessages(maya).await()
        assertEquals(0L, runtime.messageCount(maya))
        assertTrue(runtime.appState.value!!.directConversations.any { it.peer.address == maya })
    }

    @Test
    fun theRouteAndAnIdentityAskGoThroughTheRadio() = runBlocking<Unit> {
        val runtime = start()
        val tallac = runtime.appState.value!!.address("Tallac Ridge")
        // Read, whatever it says: a peer the session has learned nothing of reads Unknown.
        assertNotNull(runtime.peerRoute(tallac).await().kind)
        runtime.fetchIdentity(tallac).await()
        runtime.lookUpRepeaterHint(
            runtime.appState.value!!.named("Tallac Ridge")!!.hint.octets.let { com.voria.umsh.models.Octets(byteArrayOf(it[0], it[1])) },
            emptyList(),
        ).await()
    }

    @Test
    fun importingSavesWithTheLinksDetailsAndCanStartTheConversation() = runBlocking<Unit> {
        val runtime = start()
        val signed = ImportFixtures.signedLink(0x31, name = "Marmot")
        val address = runtime.savePeer(signed.link, "  Ridge marmot ", startConversation = false).await()
        assertEquals(signed.address, address)
        val saved = runtime.appState.value!!.peers.first { it.address == address }
        assertTrue(saved.isSaved)
        assertEquals("Ridge marmot", saved.alias)
        assertEquals("Marmot", saved.advertisedName)
        assertFalse(runtime.appState.value!!.directConversations.any { it.peer.address == address })

        // Message: saved too, and its conversation is there to open.
        val other = ImportFixtures.address(0x32)
        val conversation = runtime.savePeer(ImportFixtures.hex(other), null, startConversation = true).await()
        assertEquals(other, conversation)
        assertTrue(runtime.appState.value!!.peers.first { it.address == other }.isSaved)
        assertTrue(runtime.appState.value!!.directConversations.any { it.peer.address == other })

        // This phone itself is refused.
        try {
            runtime.savePeer(runtime.identity.value.address, null, startConversation = false).await()
            fail("saved this phone as its own peer")
        } catch (_: MobileAppException.InvalidRequest) {
            // Nothing changed.
        }
    }
}
