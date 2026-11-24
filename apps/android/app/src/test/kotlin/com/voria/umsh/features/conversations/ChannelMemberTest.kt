package com.voria.umsh.features.conversations

import com.voria.umsh.features.conversations.ThreadFixtures.message
import com.voria.umsh.models.NodeHint
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PreviewText.Sender
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Who a channel member's sheet says they are (`conversation-info.svg` 6), read from the transcript. */
class ChannelMemberTest {
    private val bytes = byteArrayOf(0x12, 0x34, 0x56)
    private val hint = NodeHint(Octets(bytes), "BtC5")
    private val ref = MemberRef(Octets(bytes), hint)
    private val saved = ListFixtures.peer("BtC5", advertisedName = "Kestrel", address = "kestrel")
    private val unsaved = ListFixtures.peer("BtC5", advertisedName = "Kestrel", address = "kestrel", saved = false)

    private fun context(vararg peers: com.voria.umsh.models.PeerSummary) = ThreadContext(
        ListFixtures.channelChat(ListFixtures.channel("hike-club")),
        peers.associateBy { it.address },
        ListFixtures.names,
        "",
        forwardSecret = false,
    )

    @Test
    fun anUnnamedMemberIsMemberAndTheirHint() {
        val messages = listOf(message(1, senderAddress = null, senderHint = bytes, senderNodeHint = hint))
        val member = ChannelMember.of(ref, messages, context())
        assertEquals(Sender.Hint("BtC5"), member.name)
        assertNull(member.address)
        assertNull(member.distinctHandle)
        assertNull(member.savedPeer)
        assertEquals("BtC5", member.nodeHint?.text)
    }

    @Test
    fun theNameTheyCallThemselvesShowsOnlyWhenItDiffers() {
        val claimed = listOf(message(1, senderAddress = null, senderHint = bytes, senderHandle = "Kes", senderNodeHint = hint))
        assertEquals(Sender.Named("Kes"), ChannelMember.of(ref, claimed, context()).name)
        assertNull(ChannelMember.of(ref, claimed, context()).distinctHandle)
        // Known by a name this phone holds, their own claim shows beside it.
        val known = listOf(message(1, senderAddress = "kestrel", senderHint = bytes, senderHandle = "Kes", senderNodeHint = hint))
        val member = ChannelMember.of(ref, known, context(saved))
        assertEquals(Sender.Named("Kestrel"), member.name)
        assertEquals("Kes", member.distinctHandle)
        assertEquals(saved, member.savedPeer)
    }

    @Test
    fun anAnsweredIdentityWinsOverAStragglerAndOnlySavedNodesLead() {
        val messages = listOf(
            message(1, senderAddress = null, senderHint = bytes, senderNodeHint = hint),
            message(2, senderAddress = "kestrel", senderHint = bytes, senderNodeHint = hint),
            message(3, senderAddress = "other", senderHint = byteArrayOf(9, 9, 9)),
            message(4, outbound = true, senderHint = bytes),
        )
        val member = ChannelMember.of(ref, messages, context(unsaved))
        assertEquals("kestrel", member.address)
        assertEquals(unsaved, member.peer)
        // Stored but not saved: the sheet asks rather than leading to a page.
        assertNull(member.savedPeer)
    }

    @Test
    fun aMemberWhoseMessagesLeftTheWindowKeepsTheirHint() {
        val member = ChannelMember.of(ref, emptyList(), context())
        assertEquals(Sender.Hint("BtC5"), member.name)
        assertEquals(hint, member.nodeHint)
    }
}
