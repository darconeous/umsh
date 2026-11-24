package com.voria.umsh.app

import androidx.compose.runtime.mutableStateOf
import androidx.navigation3.runtime.NavBackStack
import androidx.navigation3.runtime.NavKey
import com.voria.umsh.features.channels.ChannelKeyText
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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

    @Test
    fun aScannedCodeGoesBackToWhereTheScanBeganOnce() {
        shell.openScanner(ScanTarget.Root, Destination.Peers)
        shell.openScanner(ScanTarget.Root, Destination.Peers)
        val scanner = UmshKey.Scanner(ScanTarget.Root, Destination.Peers)
        assertEquals(listOf(UmshKey.Shell, scanner), shell.appStack.toList())

        shell.deliverScan(scanner, "umsh:n:x")

        assertEquals(listOf(UmshKey.Shell), shell.appStack.toList())
        // Not for another place's scan; then taken once by its own.
        assertEquals(null, shell.takeScan(ScanTarget.Root, Destination.Conversations))
        assertEquals(null, shell.takeScan(ScanTarget.AddPeerField, Destination.Peers))
        assertEquals("umsh:n:x", shell.takeScan(ScanTarget.Root, Destination.Peers))
        assertEquals(null, shell.takeScan(ScanTarget.Root, Destination.Peers))
        assertEquals(null, shell.pendingScan)
    }

    @Test
    fun aLinksPageOpensAboveTheShellOnceAndClosesBackToTheOtherApp() {
        shell.openRadioDetail()
        shell.openPeer("radio", destination = null)
        // A page Radio Detail opened is not a link's: Back stays in the app.
        assertEquals(false, shell.closingLeavesApp)

        shell.openLinkedPeer("marmot", LinkOrigin.OtherApp)
        shell.openRoute(UmshKey.PeerPage("marmot", null, LinkOrigin.OtherApp))
        // Above the link's page, Back pops to it.
        assertEquals(false, shell.closingLeavesApp)
        // The same node's link again: its page, fresh, in place of the first and what was above it.
        shell.openLinkedPeer("marmot", LinkOrigin.InApp)
        assertEquals(
            listOf(UmshKey.Shell, UmshKey.RadioDetail, UmshKey.PeerPage("radio", null), UmshKey.PeerPage("marmot", null, LinkOrigin.InApp)),
            shell.appStack.toList(),
        )
        assertEquals(false, shell.closingLeavesApp)

        // Another node's link from another app: a second page above, which leaves for that app.
        shell.openLinkedPeer("kestrel", LinkOrigin.OtherApp)
        assertEquals(true, shell.closingLeavesApp)
        shell.popAppPage()
        assertEquals(UmshKey.PeerPage("marmot", null, LinkOrigin.InApp), shell.appStack.last())
        // Selecting nothing: the destination shown never changes under a link.
        assertEquals(Destination.Conversations, shell.selected)
    }

    @Test
    fun aLinksPageLeftSomeOtherWayClosesToTheShell() {
        shell.openLinkedPeer("marmot", LinkOrigin.OtherApp)
        assertEquals(true, shell.closingLeavesApp)
        // Home, then back by the launcher: the link's flow is over.
        shell.appLeft()
        assertEquals(false, shell.closingLeavesApp)

        // Another app's link opens a second page: it leads back out again, until it is closed that way.
        shell.openLinkedPeer("kestrel", LinkOrigin.OtherApp)
        assertEquals(true, shell.closingLeavesApp)
        shell.popAppPage()
        shell.appLeft()
        // The page beneath, brought back by the launcher, closes to the shell.
        assertEquals(UmshKey.PeerPage("marmot", null, LinkOrigin.OtherApp), shell.appStack.last())
        assertEquals(false, shell.closingLeavesApp)
    }

    @Test
    fun messageOnALinksPageLeavesForConversations() {
        shell.openLinkedPeer("marmot", LinkOrigin.OtherApp)
        shell.openConversationFrom(UmshKey.PeerPage("marmot", null, LinkOrigin.OtherApp), "marmot")
        assertEquals(listOf(UmshKey.Shell), shell.appStack.toList())
        assertEquals(Destination.Conversations, shell.selected)
        assertEquals(UmshKey.Thread("marmot"), stack(Destination.Conversations).last())
    }

    @Test
    fun aChannelLinkOpensJoinChannelOverSettingsChannels() {
        stack(Destination.Settings).add(UmshKey.Notifications)
        shell.appStack.add(UmshKey.RadioDetail)

        shell.openChannelLink("umsh:gs:hike-club")

        assertEquals(Destination.Settings, shell.selected)
        assertEquals(listOf(UmshKey.SettingsRoot, UmshKey.Channels), stack(Destination.Settings).toList())
        assertEquals(listOf(UmshKey.Shell, UmshKey.ChannelJoin("umsh:gs:hike-club", opening = 1)), shell.appStack.toList())
        // The same link again is a new page, not the one it replaces (whose field may have been edited).
        shell.openChannelLink("umsh:gs:hike-club")
        assertEquals(listOf(UmshKey.Shell, UmshKey.ChannelJoin("umsh:gs:hike-club", opening = 2)), shell.appStack.toList())
        // A join from Settings stays there; New channel chat's opens the conversation.
        shell.leaveChannelJoin(UmshKey.ChannelJoin("umsh:gs:hike-club", opening = 2), null)
        assertEquals(listOf(UmshKey.Shell), shell.appStack.toList())
        assertEquals(Destination.Settings, shell.selected)
        shell.openChannelJoin(forChat = true)
        shell.leaveChannelJoin(UmshKey.ChannelJoin(forChat = true), "chat")
        assertEquals(Destination.Conversations, shell.selected)
        assertEquals(listOf(UmshKey.ConversationsRoot, UmshKey.Thread("chat")), stack(Destination.Conversations).toList())
        assertEquals(listOf(UmshKey.Shell), shell.appStack.toList())

        // A private invitation's key stays out of the key, which is saved state (§3.8).
        val invitation = "umsh:gk:" + "A".repeat(43)
        shell.openChannelLink(invitation)
        val join = shell.appStack.last() as UmshKey.ChannelJoin
        assertFalse(join.input!!.contains(invitation))
        assertFalse(join.toString().contains(invitation))
        assertEquals(invitation, ChannelKeyText.open(join.input!!))
    }

    @Test
    fun aCreatedChannelOpensOnItsPageAboveChannels() {
        shell.openChannelCreate()
        shell.openChannelCreate()
        assertEquals(listOf(UmshKey.Shell, UmshKey.ChannelCreate), shell.appStack.toList())

        shell.leaveChannelCreate("A")

        assertEquals(listOf(UmshKey.Shell), shell.appStack.toList())
        assertEquals(Destination.Settings, shell.selected)
        assertEquals(listOf(UmshKey.SettingsRoot, UmshKey.Channels, UmshKey.ChannelPage("A")), stack(Destination.Settings).toList())
    }

    @Test
    fun aLeftChannelsPageClosesWithWhatIsAboveIt() {
        stack(Destination.Settings).addAll(listOf(UmshKey.Channels, UmshKey.ChannelPage("left"), Above("sheet")))
        shell.closeChannelPagesNotIn(setOf("kept"))
        assertEquals(listOf(UmshKey.SettingsRoot, UmshKey.Channels), stack(Destination.Settings).toList())
        shell.openChannelPage("kept")
        shell.closeChannelPagesNotIn(setOf("kept"))
        assertEquals(listOf(UmshKey.SettingsRoot, UmshKey.Channels, UmshKey.ChannelPage("kept")), stack(Destination.Settings).toList())
    }

    /** Conversation info above its thread, the channel's page above that; Conversation there returns to the thread. */
    @Test
    fun conversationInfoAndItsChannelPageStackAboveTheThread() {
        shell.openDetail(Destination.Conversations, UmshKey.Thread("ch:a"))
        shell.openConversationInfo("ch:a")
        shell.openConversationInfo("ch:a")
        shell.openChannelPageFromInfo("A")
        val page = UmshKey.ChannelPage("A", Destination.Conversations)
        assertEquals(
            listOf(UmshKey.ConversationsRoot, UmshKey.Thread("ch:a"), UmshKey.ConversationInfo("ch:a"), page),
            stack(Destination.Conversations).toList(),
        )
        shell.openConversationFrom(page, "ch:a")
        assertEquals(listOf(UmshKey.ConversationsRoot, UmshKey.Thread("ch:a")), stack(Destination.Conversations).toList())

        // Left from its page there: the page closes with the channel, the thread and its info with the conversation.
        shell.openConversationInfo("ch:a")
        shell.openChannelPageFromInfo("A")
        shell.closeChannelPagesNotIn(emptySet())
        assertEquals(
            listOf(UmshKey.ConversationsRoot, UmshKey.Thread("ch:a"), UmshKey.ConversationInfo("ch:a")),
            stack(Destination.Conversations).toList(),
        )
        shell.closeThreadsNotIn(emptySet())
        assertEquals(listOf(UmshKey.ConversationsRoot), stack(Destination.Conversations).toList())
    }

    /** From Settings, the channel page's Conversation opens the conversation on Conversations. */
    @Test
    fun aSettingsChannelPagesConversationOpensOnConversations() {
        shell.select(Destination.Settings)
        shell.openChannelPage("A")
        shell.openConversationFrom(UmshKey.ChannelPage("A"), "ch:a")
        assertEquals(Destination.Conversations, shell.selected)
        assertEquals(listOf(UmshKey.ConversationsRoot, UmshKey.Thread("ch:a")), stack(Destination.Conversations).toList())
    }
}
