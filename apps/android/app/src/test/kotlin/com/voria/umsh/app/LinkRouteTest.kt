package com.voria.umsh.app

import com.voria.umsh.core.nodeUriForAddress
import com.voria.umsh.features.peers.ImportFixtures
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The one route for `umsh:` links ([LinkRoute], product-structure "Deep
 * links"), over the real core's rules, and the requests waiting for the
 * shell ([OpenRequests]).
 */
class LinkRouteTest {
    private val view = "android.intent.action.VIEW"

    @Test
    fun onlyAUmshViewIntentCarriesALink() {
        assertEquals("umsh:n:abc", LinkRoute.linkOf(view, "umsh", "umsh:n:abc"))
        // The scheme in any case: Android lowercases it, other senders may not.
        assertEquals("UMSH:n:abc", LinkRoute.linkOf(view, "UMSH", "UMSH:n:abc"))
        // A notification's tap never reaches the route, whatever its action.
        assertNull(LinkRoute.linkOf(view, "umsh-notification", "umsh-notification:open/abc"))
        assertNull(LinkRoute.linkOf(null, "umsh-notification", "umsh-notification:peer/abc"))
        // Not a view, or nothing to view.
        assertNull(LinkRoute.linkOf("android.intent.action.MAIN", "umsh", "umsh:n:abc"))
        assertNull(LinkRoute.linkOf(view, null, null))
        assertNull(LinkRoute.linkOf(view, "umsh", " "))
        assertNull(LinkRoute.linkOf(view, "https", "https://umsh.dev"))
    }

    @Test
    fun onlyAnIntentThatIsNoLinkNorABrowsersOpensTheAppsExtras() {
        val browsable = setOf("android.intent.category.BROWSABLE")
        // A notification's or shortcut's tap.
        assertTrue(LinkRoute.honorsAppExtras(null, null))
        assertTrue(LinkRoute.honorsAppExtras(null, setOf("android.intent.category.LAUNCHER")))
        // A link, from any sender, opens only its link; a browser's intent opens nothing of the app's.
        assertFalse(LinkRoute.honorsAppExtras("umsh:n:abc", null))
        assertFalse(LinkRoute.honorsAppExtras("umsh:n:abc", browsable))
        assertFalse(LinkRoute.honorsAppExtras(null, browsable))
        assertTrue(LinkRoute.fromBrowser(browsable))
        assertFalse(LinkRoute.fromBrowser(null))
    }

    @Test
    fun linksLeadWhereProductStructureSays() {
        val own = ImportFixtures.address(0x21)
        val other = ImportFixtures.signedLink(0x22)
        // Every channel prefix, the deprecated ones too, whatever the scheme's case.
        for (prefix in listOf("umsh:gs:", "umsh:gk:", "umsh:cs:", "UMSH:ck:")) {
            val link = "${prefix}abc"
            assertEquals(prefix, LinkTarget.Channel(link), LinkRoute.target(link, own))
        }
        assertEquals(LinkTarget.Unreadable("umsh:x:Mx4eTq8VbN3k"), LinkRoute.target("umsh:x:Mx4eTq8VbN3k", own))
        assertEquals(LinkTarget.Unreadable("umsh:n:"), LinkRoute.target("umsh:n:", own))
        assertEquals(LinkTarget.OwnIdentity, LinkRoute.target(nodeUriForAddress(own), own))
        assertEquals(LinkTarget.Node(other.link, other.address), LinkRoute.target(other.link, own))
        val bare = nodeUriForAddress(other.address)
        assertEquals(LinkTarget.Node(bare, other.address), LinkRoute.target(bare, own))
    }

    @Test
    fun oneLinkAndOneTapWaitInTheOrderTheyArrived() {
        val requests = OpenRequests()
        val first = OpenRequest.Link("umsh:n:a", LinkOrigin.OtherApp)
        requests.offer(first)
        requests.offer(OpenRequest.Conversation("x"))
        val tap = OpenRequest.Peer("y")
        requests.offer(tap)
        assertEquals(listOf(first, tap), requests.pending.value)

        // A newer link replaces the one waiting, and comes after the tap.
        val second = OpenRequest.Link("umsh:n:b", LinkOrigin.InApp)
        requests.offer(second)
        assertEquals(listOf(tap, second), requests.pending.value)
        assertEquals(second, requests.link)

        requests.done(tap)
        assertEquals(listOf(second), requests.pending.value)
        requests.done(second)
        assertEquals(emptyList<OpenRequest>(), requests.pending.value)
        assertNull(requests.link)
    }

    @Test
    fun aRepeatOfTheRequestBeingOpenedIsThatRequest() {
        val requests = OpenRequests()
        requests.offer(OpenRequest.Link("umsh:n:a", LinkOrigin.OtherApp))
        val opening = requests.pending.value.first()
        // The same link again while the shell opens the first: nothing new
        // waits, so nothing is left behind once the first is done.
        requests.offer(OpenRequest.Link("umsh:n:a", LinkOrigin.OtherApp))
        assertEquals(listOf(opening), requests.pending.value)
        requests.done(opening)
        assertEquals(emptyList<OpenRequest>(), requests.pending.value)

        // A tap that arrives meanwhile still waits, alone.
        requests.offer(opening)
        requests.offer(OpenRequest.Conversation("b"))
        requests.offer(OpenRequest.Link("umsh:n:a", LinkOrigin.OtherApp))
        requests.done(opening)
        assertEquals(listOf(OpenRequest.Conversation("b")), requests.pending.value)
    }
}
