package com.voria.umsh.app

import androidx.compose.runtime.mutableStateOf
import androidx.navigation3.runtime.NavBackStack
import androidx.navigation3.runtime.NavKey
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * [ShellState.closePeerPagesNotIn] over every stack, and a page never
 * pushed twice onto one. The closing tests' keys are this test's own.
 */
class ShellStateTest {
    private data class PeerPage(override val peerAddress: String?) : NavKey, PeerPageKey

    private data class Above(val name: String) : NavKey

    private val shell = ShellState(
        mutableStateOf(Destination.Conversations),
        Destination.entries.associateWith { NavBackStack<NavKey>(it.root) },
        NavBackStack(UmshKey.Shell),
    )

    private fun stack(destination: Destination) = shell.stacks.getValue(destination)

    @Test
    fun aGonePeersPagesCloseWithWhatIsAboveThemEverywhere() {
        stack(Destination.Peers).addAll(listOf(PeerPage("kept"), PeerPage("gone"), Above("route")))
        stack(Destination.Conversations).addAll(listOf(UmshKey.Thread("gone"), PeerPage("gone"), Above("route")))
        stack(Destination.Settings).addAll(listOf(UmshKey.RadioDetail, PeerPage("gone")))
        shell.appStack.addAll(listOf(UmshKey.RadioDetail, PeerPage("gone"), Above("editor")))

        shell.closePeerPagesNotIn(setOf("kept"))

        assertEquals(listOf(UmshKey.PeersRoot, PeerPage("kept")), stack(Destination.Peers).toList())
        // The thread is closeThreadsNotIn's; only the page about the peer goes here.
        assertEquals(listOf(UmshKey.ConversationsRoot, UmshKey.Thread("gone")), stack(Destination.Conversations).toList())
        assertEquals(listOf(UmshKey.SettingsRoot, UmshKey.RadioDetail), stack(Destination.Settings).toList())
        assertEquals(listOf(UmshKey.Shell, UmshKey.RadioDetail), shell.appStack.toList())
    }

    @Test
    fun pagesOfStoredPeersAndPagesNamingNoneStay() {
        val pages = listOf(PeerPage("kept"), PeerPage(null), Above("route"))
        stack(Destination.Peers).addAll(pages)
        shell.appStack.addAll(pages)

        shell.closePeerPagesNotIn(setOf("kept"))

        assertEquals(listOf(UmshKey.PeersRoot) + pages, stack(Destination.Peers).toList())
        assertEquals(listOf(UmshKey.Shell) + pages, shell.appStack.toList())
    }

    @Test
    fun noPeersClosesEveryPeerPage() {
        stack(Destination.Peers).addAll(listOf(PeerPage("a"), PeerPage("b")))
        shell.closePeerPagesNotIn(emptySet())
        assertEquals(listOf(UmshKey.PeersRoot), stack(Destination.Peers).toList())
    }

    /** A hop on X's route opens Y, whose route runs back through X: back to X's page, not a second copy. */
    @Test
    fun aRouteThatLoopsBackReturnsToThePageAlreadyOpen() {
        val x = UmshKey.PeerPage("x", Destination.Peers)
        shell.openPeerFromList("x")
        shell.openRoute(x)
        shell.openPeer("y", Destination.Peers)
        shell.openRoute(UmshKey.PeerPage("y", Destination.Peers))
        shell.openPeer("x", Destination.Peers)
        assertEquals(listOf(UmshKey.PeersRoot, x), stack(Destination.Peers).toList())

        shell.appStack.add(UmshKey.RadioDetail)
        shell.openPeer("z", null)
        shell.openRoute(UmshKey.PeerPage("z", null))
        shell.openPeer("z", null)
        assertEquals(listOf(UmshKey.Shell, UmshKey.RadioDetail, UmshKey.PeerPage("z", null)), shell.appStack.toList())
    }

    /**
     * D12: Neighbors and Discover push on the stack of the page that opened
     * them, above the shell with it; the list's Discover peers is its one
     * detail page. Discover aimed at a peer closes with it; the nearby one
     * names no peer and stays.
     */
    @Test
    fun neighborsAndDiscoverGoOnTheOpenersStack() {
        val page = UmshKey.PeerPage("x", Destination.Conversations)
        stack(Destination.Conversations).add(UmshKey.Thread("x"))
        shell.openPeer("x", Destination.Conversations)
        shell.openNeighbors(page)
        assertEquals(UmshKey.Neighbors("x", Destination.Conversations), stack(Destination.Conversations).last())
        shell.pop()
        shell.openRoute(page)
        shell.openDiscover(UmshKey.Route("x", Destination.Conversations))
        assertEquals(UmshKey.Discover("x", Destination.Conversations), stack(Destination.Conversations).last())

        shell.openPeer("y", null)
        shell.openNeighbors(UmshKey.PeerPage("y", null))
        assertEquals(UmshKey.Neighbors("y", null), shell.appStack.last())

        shell.openPeerFromList("z")
        shell.openDiscoverFromList()
        assertEquals(listOf(UmshKey.PeersRoot, UmshKey.Discover(null, Destination.Peers)), stack(Destination.Peers).toList())

        shell.closePeerPagesNotIn(setOf("z"))
        assertEquals(listOf(UmshKey.ConversationsRoot, UmshKey.Thread("x")), stack(Destination.Conversations).toList())
        assertEquals(listOf(UmshKey.Shell), shell.appStack.toList())
        assertEquals(listOf(UmshKey.PeersRoot, UmshKey.Discover(null, Destination.Peers)), stack(Destination.Peers).toList())
    }

    @Test
    fun addPeerLeavesForAPageOnItsOwnStack() {
        shell.openAddPeer(Destination.Peers)
        val addPeer = UmshKey.AddPeer(Destination.Peers)
        assertEquals(listOf(UmshKey.PeersRoot, addPeer), stack(Destination.Peers).toList())

        shell.leaveAddPeerForPage(addPeer, "node")

        // The page takes Add peer's place: Back from it is the list.
        assertEquals(listOf(UmshKey.PeersRoot, UmshKey.PeerPage("node", Destination.Peers)), stack(Destination.Peers).toList())
    }

    @Test
    fun newMessagesAddPeerIsOnConversationsAndLeavesForTheThread() {
        stack(Destination.Conversations).add(UmshKey.Thread("open"))
        shell.openAddPeer(Destination.Conversations)
        val addPeer = UmshKey.AddPeer(Destination.Conversations)
        // As the list's one detail page, in place of the open thread (D11).
        assertEquals(listOf(UmshKey.ConversationsRoot, addPeer), stack(Destination.Conversations).toList())

        shell.leaveAddPeerForPage(addPeer, "node")
        assertEquals(
            listOf(UmshKey.ConversationsRoot, UmshKey.PeerPage("node", Destination.Conversations)),
            stack(Destination.Conversations).toList(),
        )

        shell.openAddPeer(Destination.Conversations)
        shell.leaveAddPeerForConversation(addPeer, "node")
        assertEquals(Destination.Conversations, shell.selected)
        assertEquals(listOf(UmshKey.ConversationsRoot, UmshKey.Thread("node")), stack(Destination.Conversations).toList())
    }

    @Test
    fun peersAddPeerClosesWhenItsMessageOpensTheThread() {
        shell.select(Destination.Peers)
        shell.openAddPeer(Destination.Peers)
        shell.leaveAddPeerForConversation(UmshKey.AddPeer(Destination.Peers), "node")

        assertEquals(listOf(UmshKey.PeersRoot), stack(Destination.Peers).toList())
        assertEquals(Destination.Conversations, shell.selected)
        assertEquals(listOf(UmshKey.ConversationsRoot, UmshKey.Thread("node")), stack(Destination.Conversations).toList())
    }

    @Test
    fun ownIdentityInAddPeerOpensYourIdentity() {
        shell.select(Destination.Peers)
        shell.openAddPeer(Destination.Peers)
        shell.leaveAddPeerForIdentity(UmshKey.AddPeer(Destination.Peers), twoPane = false)
        assertEquals(listOf(UmshKey.PeersRoot), stack(Destination.Peers).toList())
        assertEquals(Destination.Settings, shell.selected)
        assertEquals(listOf(UmshKey.SettingsRoot, UmshKey.YourIdentity), stack(Destination.Settings).toList())

        // Beside the Settings list, its root shows Your identity already.
        shell.openAddPeer(Destination.Conversations)
        shell.leaveAddPeerForIdentity(UmshKey.AddPeer(Destination.Conversations), twoPane = true)
        assertEquals(listOf(UmshKey.SettingsRoot), stack(Destination.Settings).toList())
        assertEquals(listOf(UmshKey.ConversationsRoot), stack(Destination.Conversations).toList())
    }

    // --- The exchange page follows the exchange (nearby-exchange.svg) -----

    @Test
    fun anAttemptUnderWayPushesTheExchangeOverAddPeerOnce() {
        shell.select(Destination.Peers)
        shell.openAddPeer(Destination.Peers)
        shell.followMeet(MeetStep.None)
        assertEquals(listOf(UmshKey.PeersRoot, UmshKey.AddPeer(Destination.Peers)), stack(Destination.Peers).toList())
        shell.followMeet(MeetStep.UnderWay)
        shell.followMeet(MeetStep.UnderWay)
        assertEquals(
            listOf(UmshKey.PeersRoot, UmshKey.AddPeer(Destination.Peers), UmshKey.Exchange(Destination.Peers)),
            stack(Destination.Peers).toList(),
        )
    }

    @Test
    fun anAttemptOverClosesTheExchangeAndOnlyIt() {
        shell.openAddPeer(Destination.Conversations)
        shell.followMeet(MeetStep.UnderWay)
        shell.followMeet(MeetStep.None)
        assertEquals(listOf(UmshKey.ConversationsRoot, UmshKey.AddPeer(Destination.Conversations)), stack(Destination.Conversations).toList())
        // Add peer itself stays: the exchange never closes it.
        shell.followMeet(MeetStep.None)
        assertEquals(UmshKey.AddPeer(Destination.Conversations), stack(Destination.Conversations).last())
    }

    @Test
    fun contactsCrossedReplaceAddPeerAndTheExchangeWithThePage() {
        shell.select(Destination.Peers)
        shell.openAddPeer(Destination.Peers)
        shell.followMeet(MeetStep.UnderWay)
        shell.followMeet(MeetStep.Exchanged("kestrel"))
        assertEquals(listOf(UmshKey.PeersRoot, UmshKey.PeerPage("kestrel", Destination.Peers)), stack(Destination.Peers).toList())
        // Asked over Add peer, answered there, exchanged before the page was pushed: the same.
        shell.openAddPeer(Destination.Peers)
        shell.followMeet(MeetStep.Exchanged("marmot"))
        assertEquals(listOf(UmshKey.PeersRoot, UmshKey.PeerPage("marmot", Destination.Peers)), stack(Destination.Peers).toList())
    }

    @Test
    fun aRestoredExchangeWithNoExchangeClosesItself() {
        // After process death the exchange key comes back; the exchange does not.
        stack(Destination.Peers).addAll(listOf(UmshKey.AddPeer(Destination.Peers), UmshKey.Exchange(Destination.Peers)))
        shell.select(Destination.Peers)
        shell.followMeet(MeetStep.None)
        assertEquals(listOf(UmshKey.PeersRoot, UmshKey.AddPeer(Destination.Peers)), stack(Destination.Peers).toList())
    }

    @Test
    fun anAppPageOverTheShellHoldsTheExchangeUntilItCloses() {
        shell.select(Destination.Peers)
        shell.openAddPeer(Destination.Peers)
        shell.openRadioDetail()
        assertEquals(UmshKey.RadioDetail, shell.shownTop)
        // Nothing is pushed under Radio Detail.
        shell.followMeet(MeetStep.UnderWay)
        shell.followMeet(MeetStep.Exchanged("kestrel"))
        assertEquals(listOf(UmshKey.PeersRoot, UmshKey.AddPeer(Destination.Peers)), stack(Destination.Peers).toList())
        shell.popAppPage()
        assertEquals(UmshKey.AddPeer(Destination.Peers), shell.shownTop)
        shell.followMeet(MeetStep.UnderWay)
        assertEquals(UmshKey.Exchange(Destination.Peers), stack(Destination.Peers).last())
    }

    @Test
    fun onlyTheShownTopFollows() {
        // Add peer under another page, or on a stack not shown: nothing moves.
        stack(Destination.Peers).addAll(listOf(UmshKey.AddPeer(Destination.Peers), UmshKey.Exchange(Destination.Peers)))
        shell.openAddPeer(Destination.Conversations)
        shell.push(Destination.Conversations, UmshKey.YourIdentity)
        shell.followMeet(MeetStep.UnderWay)
        shell.followMeet(MeetStep.None)
        shell.followMeet(MeetStep.Exchanged("kestrel"))
        assertEquals(
            listOf(UmshKey.ConversationsRoot, UmshKey.AddPeer(Destination.Conversations), UmshKey.YourIdentity),
            stack(Destination.Conversations).toList(),
        )
        assertEquals(3, stack(Destination.Peers).size)
    }
}
