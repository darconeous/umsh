package com.voria.umsh.features.conversations

import com.voria.umsh.core.MobileAppConfigRecord
import com.voria.umsh.core.MobileAppCore
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.core.MobileAppStore
import com.voria.umsh.core.SecretVault
import com.voria.umsh.features.conversations.ListFixtures.channel
import com.voria.umsh.features.conversations.ListFixtures.channelChat
import com.voria.umsh.features.conversations.ListFixtures.direct
import com.voria.umsh.features.conversations.ListFixtures.names
import com.voria.umsh.features.conversations.ListFixtures.peer
import com.voria.umsh.features.conversations.ListFixtures.preview
import com.voria.umsh.features.conversations.ListFixtures.state
import com.voria.umsh.features.peers.PeerSections
import com.voria.umsh.models.PreviewText
import com.voria.umsh.models.PreviewText.Sender
import com.voria.umsh.services.format.SearchFolding
import com.voria.umsh.services.format.SearchQuery
import com.voria.umsh.services.mobilecore.ParityFormat
import com.voria.umsh.services.mobilecore.RecordMapping
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** The conversation list's rules (`conversation-list.svg`), and the Peers list's sections. */
class ConversationListTest {
    @get:Rule val temp = TemporaryFolder()

    private val collation = JvmCollation()

    private fun rows(vararg conversations: Any, peers: List<com.voria.umsh.models.PeerSummary> = emptyList(), own: String? = null) =
        ConversationList.rows(
            state(
                peers = peers,
                direct = conversations.filterIsInstance<com.voria.umsh.models.DirectConversationSummary>(),
                channelChats = conversations.filterIsInstance<com.voria.umsh.models.ChannelConversationSummary>(),
            ),
            names,
            collation,
            own,
        )

    @Test
    fun previewsTakeTheFirstThatApplies() {
        val kestrel = peer("7NQL", advertisedName = "Kestrel")
        val ana = peer("AnA1", advertisedName = "Ana")
        val hike = channel("hike-club")
        fun previewOf(conversation: com.voria.umsh.models.ConversationSummary, own: String? = null) =
            PreviewText.of(conversation, mapOf(ana.address to ana), names, own)

        // A draft wins over everything, even a deleted last message.
        assertEquals(
            PreviewText.Draft("Bring the spare antenna"),
            previewOf(channelChat(hike, preview(1, deleted = true), draft = "Bring the spare\nantenna")),
        )
        assertEquals(PreviewText.Deleted, previewOf(direct(kestrel, preview(1, deleted = true))))
        assertEquals(PreviewText.None, previewOf(direct(kestrel)))
        // A whitespace-only draft is no draft.
        assertEquals(PreviewText.None, previewOf(direct(kestrel, draft = "  ")))
        assertEquals(PreviewText.Mine("Thanks! Got it."), previewOf(direct(kestrel, preview(1, "Thanks! Got it.", outbound = true))))
        assertEquals(PreviewText.Plain("Copy."), previewOf(direct(kestrel, preview(1, "Copy."))))
        // Status text: mine under the advertised name, "You" with none; theirs under the title.
        assertEquals(
            PreviewText.Status(Sender.Me("Juniper"), "waves"),
            previewOf(direct(kestrel, preview(1, "waves", outbound = true, status = true)), own = "Juniper"),
        )
        assertEquals(
            PreviewText.Status(Sender.Me(null), "waves"),
            previewOf(direct(kestrel, preview(1, "waves", outbound = true, status = true)), own = ""),
        )
        assertEquals(
            PreviewText.Status(Sender.Named("Kestrel"), "is at the saddle"),
            previewOf(direct(kestrel, preview(1, "is at the saddle", status = true))),
        )
    }

    @Test
    fun aChannelMemberIsNamedOrLabeledByHint() {
        val ana = peer("AnA1", advertisedName = "Ana")
        val unnamed = peer("BtC5")
        val peers = listOf(ana, unnamed).associateBy { it.address }
        val hike = channel("hike-club")
        fun previewOf(last: com.voria.umsh.models.ConversationPreview) =
            PreviewText.of(channelChat(hike, last), peers, names, null)

        assertEquals(
            PreviewText.Member(Sender.Named("Ana"), "Trail’s clear"),
            previewOf(preview(1, "Trail’s clear", senderAddress = ana.address, senderHint = "AnA1")),
        )
        // A known peer with no name is still only its hint: never "Unnamed node", never an address.
        assertEquals(
            PreviewText.Member(Sender.Hint("BtC5"), "hi"),
            previewOf(preview(1, "hi", senderAddress = unnamed.address, senderHint = "BtC5")),
        )
        assertEquals(PreviewText.Member(Sender.Hint("Zz9q"), "hi"), previewOf(preview(1, "hi", senderHint = "Zz9q")))
        assertEquals(PreviewText.Member(Sender.Unknown, "hi"), previewOf(preview(1, "hi")))
        assertEquals(PreviewText.Mine("ok"), previewOf(preview(1, "ok", outbound = true)))
    }

    @Test
    fun rowsAreNewestActivityFirstThenByTitle() {
        val kestrel = direct(peer("7NQL", advertisedName = "Kestrel"), preview(300))
        val opened = direct(peer("BtC5"), created = 500) // no messages: as recent as its opening
        val public = channelChat(channel("Public", canonical = "public", notifications = false), preview(100))
        val ember = direct(peer("EmB1", advertisedName = "ember"), preview(100))
        val alder = direct(peer("AlD1", advertisedName = "Älder"), preview(100))

        val shown = rows(kestrel, opened, public, ember, alder)

        assertEquals(listOf("Unnamed node", "Kestrel", "Älder", "ember", "Public"), shown.map { it.title })
        assertNull(shown.first().timeMs)
        assertEquals(300L, shown[1].timeMs)
        assertTrue(shown.single { it.title == "Public" }.muted)
        assertEquals(Removal.Leave("ch:${public.channel.id}", "Public"), shown.single { it.title == "Public" }.removal)
        assertEquals(Removal.Delete(kestrel.address, "Kestrel"), shown[1].removal)
    }

    @Test
    fun searchGroupsAsIosDoes() {
        val ridge = peer("AP5R", advertisedName = "Ridge Medic")
        val skinner = peer("Bq7d", advertisedName = "Skinner Ridge", role = com.voria.umsh.models.PeerRole.Repeater)
        val riverbend = peer("Ri4x", advertisedName = "Riverbend", saved = false)
        val radio = peer("Tr4d", advertisedName = "Trail radio", companion = true)
        val ridgeline = channel("Ridgeline", kind = com.voria.umsh.models.ChannelKind.PrivateKey)
        val hike = channel("hike-club")
        val left = channel("Ridge runners", joined = false)
        val state = state(
            peers = listOf(ridge, skinner, riverbend, radio),
            channels = listOf(ridgeline, hike, left),
            direct = listOf(direct(ridge, preview(10))),
            channelChats = listOf(channelChat(hike, preview(5))),
        )
        val shown = ConversationList.rows(state, names, collation, null)

        val found = ConversationList.search(state, shown, "ri", names, collation)!!

        assertEquals(listOf("Ridge Medic"), found.conversations.map { it.title })
        // A peer with a conversation is found through it; the radio is not a correspondent.
        assertEquals(listOf(skinner), found.peers)
        // Joined and without a chat; a channel left is not offered.
        assertEquals(listOf(ridgeline), found.channels)
        assertEquals(listOf(riverbend), found.discovered)

        assertTrue(ConversationList.search(state, shown, "zq", names, collation)!!.isEmpty)
        assertNull(ConversationList.search(state, shown, "  ", names, collation))
    }

    @Test
    fun searchFoldsNamesButNotAddresses() {
        val jose = peer("JoS3", advertisedName = "José", address = "9vXqAddress")
        assertTrue(ConversationList.matches(jose, SearchQuery("jose")))
        assertTrue(ConversationList.matches(jose, SearchQuery("JOSÉ")))
        assertTrue(ConversationList.matches(jose, SearchQuery("9vXq")))
        // Addresses match on a prefix only, and exactly: base58 is case-sensitive.
        assertFalse(ConversationList.matches(jose, SearchQuery("Address")))
        assertFalse(ConversationList.matches(jose, SearchQuery("9vxq")))
        // Hints ignore case.
        assertTrue(ConversationList.matches(jose, SearchQuery("jos3")))

        val public = channel("Public", canonical = "public", hex = "8f02ca")
        assertTrue(ConversationList.matches(public, SearchQuery("publ"), names))
        assertTrue(ConversationList.matches(public, SearchQuery("8F02"), names))
        assertFalse(ConversationList.matches(public, SearchQuery("02ca"), names))
        assertEquals("emile", SearchFolding.fold("Émile"))
    }

    @Test
    fun anUnreadOrStartingListNeverClaimsToBeEmpty() {
        val row = rows(direct(peer("7NQL"), preview(1)))
        assertEquals(ConversationsContent.Loading, ConversationsContent.of(null, MobileAppLifecycle.Running))
        assertEquals(ConversationsContent.Loading, ConversationsContent.of(emptyList(), MobileAppLifecycle.Idle))
        assertEquals(ConversationsContent.Loading, ConversationsContent.of(emptyList(), MobileAppLifecycle.Starting))
        assertEquals(ConversationsContent.Empty, ConversationsContent.of(emptyList(), MobileAppLifecycle.Running))
        assertEquals(ConversationsContent.Rows(row), ConversationsContent.of(row, MobileAppLifecycle.Starting))
    }

    @Test
    fun peerSectionsLeaveOutNodesNotSaved() {
        val ridge = peer("AP5R", advertisedName = "Ridge Medic", favorite = true)
        val kestrel = peer("7NQL", advertisedName = "kestrel")
        val alder = peer("AlD1", alias = "Alder")
        val heard = peer("Ri4x", advertisedName = "Riverbend", saved = false)
        val radio = peer("Tr4d", advertisedName = "Trail radio", companion = true, saved = false)

        val sections = PeerSections.of(state(peers = listOf(ridge, kestrel, alder, heard, radio)), names, collation)

        assertEquals(listOf(ridge), sections.favorites)
        assertEquals(listOf(alder, kestrel), sections.saved)
        assertEquals(listOf(radio), sections.radios)
        assertTrue(PeerSections.of(state(peers = listOf(heard)), names, collation).isEmpty)
    }

    /** The seeded staging store, read through a radioless core: every conversation is a row, newest first. */
    @Test
    fun theSeededStoreListsEveryConversation() {
        val directory = ParityFormat.directory
        val copy = File(temp.newFolder(), "seeded.sqlite")
        File(directory, "seeded.sqlite").copyTo(copy)
        val golden = File(directory, "seeded.golden").readLines()
        val store = MobileAppStore.open(copy.path)
        val core = MobileAppCore(store, NoVault, MobileAppConfigRecord(temp.newFolder().path, 0u))
        try {
            core.setOwner("owner")
            val state = RecordMapping.state(core.state(false), emptyMap(), previous = null)
            val shown = ConversationList.rows(state, names, collation, null)

            val expected = golden.count { it.startsWith("direct ") || it.startsWith("channel_conversation ") }
            assertEquals(expected, shown.size)
            assertEquals(shown.map { it.lastActivityMs }.sortedDescending(), shown.map { it.lastActivityMs })
            val unread = golden.filter { it.startsWith("direct ") || it.startsWith("channel_conversation ") }
                .count { !it.contains(" unread=0 ") }
            assertEquals(unread, shown.count { it.unreadCount > 0 })
        } finally {
            core.close()
            store.close()
        }
    }

    private object NoVault : SecretVault {
        override fun load(account: String): ByteArray? = null
        override fun store(account: String, secret: ByteArray) = Unit
        override fun delete(account: String) = Unit
        override fun deleteAll() = Unit
    }
}
