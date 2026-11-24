package com.voria.umsh.features.channels

import com.voria.umsh.models.ChannelKind
import com.voria.umsh.models.ChannelSummary
import com.voria.umsh.models.Octets
import org.junit.Assert.assertEquals
import org.junit.Test

/** Which channels Settings › Channels lists, Join channel suggests, and New channel chat offers. */
class ChannelListsTest {
    private fun channel(id: String, kind: ChannelKind, joined: Boolean, conversation: String? = null) = ChannelSummary(
        id = id, kind = kind, canonicalName = null, name = id, alias = null, channelIdHex = "0000",
        tint = Octets(byteArrayOf(0, 0, 0)), regionCode = null, maxFloodHops = null, joinedPhone = joined,
        notificationsEnabled = true, joinedAtMs = null, conversationAddress = conversation,
    )

    private val channels = listOf(
        channel("public", ChannelKind.Builtin, joined = true, conversation = "p"),
        channel("emergency", ChannelKind.Builtin, joined = false),
        channel("hike", ChannelKind.Named, joined = true),
        channel("fire", ChannelKind.PrivateKey, joined = true, conversation = "f"),
        channel("left", ChannelKind.Named, joined = false),
    )

    @Test
    fun joinedSuggestedAndWithoutAConversation() {
        assertEquals(listOf("public", "hike", "fire"), ChannelLists.joined(channels).map { it.id })
        assertEquals("only built-in channels come back as suggestions", listOf("emergency"), ChannelLists.suggested(channels).map { it.id })
        assertEquals(listOf("hike"), ChannelLists.withoutConversation(channels).map { it.id })
    }
}
