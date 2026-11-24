package com.voria.umsh.features.peers

import com.voria.umsh.features.conversations.JvmCollation
import com.voria.umsh.features.conversations.ListFixtures
import com.voria.umsh.models.AppStateSnapshot
import com.voria.umsh.models.ConversationPreview
import com.voria.umsh.models.DirectConversationSummary
import com.voria.umsh.models.PeerRole
import com.voria.umsh.models.PeerSummary
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The Peers list's sections, orders, filters and search (`peers-list.svg`, iOS `PeersView`). */
class PeerSectionsTest {
    private fun arrangement(sort: PeerSort = PeerSort.Alphabetical, filter: PeerFilter? = null) =
        PeerArrangement(sort, filter, ListFixtures.names, JvmCollation())

    private fun state(peers: List<PeerSummary>, conversations: List<DirectConversationSummary> = emptyList()) =
        AppStateSnapshot(peers, emptyList(), conversations, emptyList(), emptyList(), null)

    private fun conversation(peer: PeerSummary, lastMs: Long?) = DirectConversationSummary(
        id = peer.id,
        peer = peer,
        draftText = "",
        lastReadAtMs = 0,
        createdAtMs = 0,
        notificationsEnabled = true,
        lastMessage = lastMs?.let { ConversationPreview(it, "hi", false, false, null, null, false, null) },
        unreadCount = 0,
        revision = 0,
    )

    private val kestrel = ListFixtures.peer("7NQL", "Kestrel").copy(lastHeardAtMs = 100)
    private val ridge = ListFixtures.peer("AP5R", "Ridge Medic", favorite = true).copy(lastHeardAtMs = 300)
    private val skinner = ListFixtures.peer("Bq7d", "Skinner Ridge", role = PeerRole.Repeater).copy(likelyRepeater = true, lastHeardAtMs = 200)
    private val gauge = ListFixtures.peer("4Btt", "Trailhead gauge", role = PeerRole.Sensor)
    private val tracker = ListFixtures.peer("Tk11", "Collar", role = PeerRole.Tracker)
    private val radio = ListFixtures.peer("Tr4d", "Trail radio", companion = true, saved = false, role = PeerRole.Unknown)
    private val fern = ListFixtures.peer("H1x9", "Fern Ridge", saved = false, role = PeerRole.Repeater).copy(likelyRepeater = true)
    private val all = listOf(kestrel, ridge, skinner, gauge, tracker, radio, fern)

    private fun names(peers: List<PeerSummary>) = peers.map { it.advertisedName }

    @Test
    fun sectionsHoldFavoritesSavedAndTheRadioButNotNodesOnlyHeard() {
        val sections = PeerSections.of(state(all), arrangement())
        assertEquals(listOf("Ridge Medic"), names(sections.favorites))
        assertEquals(listOf("Collar", "Kestrel", "Skinner Ridge", "Trailhead gauge"), names(sections.saved))
        assertEquals(listOf("Trail radio"), names(sections.radios))
        assertFalse(sections.nothingKnown)
    }

    @Test
    fun nothingKnownOnlyWhenNoNodeIsStored() {
        assertTrue(PeerSections.of(state(emptyList()), arrangement()).nothingKnown)
        // A node only heard is known, though no section lists it (iOS: `peers.isEmpty`).
        val heard = PeerSections.of(state(listOf(fern)), arrangement())
        assertTrue(heard.isEmpty)
        assertFalse(heard.nothingKnown)
        // A filter that empties the sections is not the empty state.
        val filtered = PeerSections.of(state(listOf(kestrel)), arrangement(filter = PeerFilter.Sensors))
        assertTrue(filtered.isEmpty)
        assertFalse(filtered.nothingKnown)
    }

    @Test
    fun recentlyHeardPutsTheNewestFirstAndNeverHeardLast() {
        val sections = PeerSections.of(state(all), arrangement(PeerSort.RecentlyHeard))
        assertEquals(listOf("Skinner Ridge", "Kestrel", "Trailhead gauge", "Collar"), names(sections.saved))
    }

    @Test
    fun latestMessageFollowsTheConversations() {
        val conversations = listOf(conversation(gauge, 500), conversation(kestrel, 900))
        val sections = PeerSections.of(state(all, conversations), arrangement(PeerSort.LatestMessage))
        assertEquals(listOf("Kestrel", "Trailhead gauge", "Skinner Ridge", "Collar"), names(sections.saved))
    }

    @Test
    fun filtersPickRolesAndTheRadioAlwaysShows() {
        val people = PeerSections.of(state(all, listOf(conversation(gauge, 1))), arrangement(filter = PeerFilter.People))
        // Chat nodes, and a sensor there is a conversation with.
        assertEquals(listOf("Ridge Medic"), names(people.favorites))
        assertEquals(listOf("Kestrel", "Trailhead gauge"), names(people.saved))
        assertEquals(listOf("Trail radio"), names(people.radios))
        val sensors = PeerSections.of(state(all), arrangement(filter = PeerFilter.Sensors))
        assertEquals(listOf("Collar", "Trailhead gauge"), names(sensors.saved))
        assertEquals(listOf("Trail radio"), names(sensors.radios))
        val repeaters = PeerSections.of(state(all), arrangement(filter = PeerFilter.Repeaters))
        assertEquals(listOf("Skinner Ridge"), names(repeaters.saved))
    }

    @Test
    fun searchSplitsSavedFromDiscoveredUnderTheSameChips() {
        val results = PeerSearchResults.of(state(all), "ridge", arrangement())
        assertEquals(listOf("Ridge Medic", "Skinner Ridge"), names(results.saved))
        assertEquals(listOf("Fern Ridge"), names(results.discovered))
        val repeaters = PeerSearchResults.of(state(all), "ridge", arrangement(filter = PeerFilter.Repeaters))
        assertEquals(listOf("Skinner Ridge"), names(repeaters.saved))
        assertEquals(listOf("Fern Ridge"), names(repeaters.discovered))
        assertTrue(PeerSearchResults.of(state(all), "zzz", arrangement()).isEmpty)
    }

    @Test
    fun searchMatchesNamesWithoutCaseOrAccentsAddressesByPrefixAndHints() {
        val jose = ListFixtures.peer("Js01", "José", address = "9xQwAddressAbc").copy(alias = "Dana")
        assertTrue(PeerSearch.matches(jose, "jose"))
        assertTrue(PeerSearch.matches(jose, "DANA"))
        assertTrue(PeerSearch.matches(jose, "9xQw"))
        // An address matches only from its start, and case-sensitively: Base58 is exact.
        assertFalse(PeerSearch.matches(jose, "Address"))
        assertFalse(PeerSearch.matches(jose, "9xqw"))
        assertTrue(PeerSearch.matches(jose, "s0"))
        assertTrue(PeerSearch.matches(jose, "  "))
    }

    @Test
    fun aStoredOrderThisBuildDoesNotKnowReadsAsAlphabetical() {
        assertEquals(PeerSort.RecentlyHeard, PeerSort.named("RecentlyHeard"))
        assertEquals(PeerSort.Alphabetical, PeerSort.named(null))
        assertEquals(PeerSort.Alphabetical, PeerSort.named("Distance"))
    }
}
