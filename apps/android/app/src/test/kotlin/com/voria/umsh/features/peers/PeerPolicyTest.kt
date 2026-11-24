package com.voria.umsh.features.peers

import com.voria.umsh.R
import com.voria.umsh.features.conversations.ListFixtures
import com.voria.umsh.models.AdvertisedIdentity
import com.voria.umsh.models.Capabilities
import com.voria.umsh.models.PeerRole
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.models.SignatureState
import com.voria.umsh.services.location.PhoneFix
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The page's verbs (iOS `PeerVerbs.offered`), removal (`peers-list.svg` 5), and the distance math. */
class PeerPolicyTest {
    private val every = PeerVerb.entries.toSet()

    private fun advertising(peer: PeerSummary, bits: Int, role: PeerRole = PeerRole.Chat, latitude: Double? = null, longitude: Double? = null, precision: Int? = null) =
        peer.copy(
            advertised = AdvertisedIdentity(
                roleCode = role.code ?: 0,
                capabilityBits = bits,
                forwards = false,
                name = peer.advertisedName,
                latitude = latitude,
                longitude = longitude,
                locationPrecision = precision,
                altitudeMeters = null,
                timestamp = null,
                signature = SignatureState.Valid,
            ),
        )

    @Test
    fun verbsFollowCapabilitiesNotRole() {
        val chat = advertising(ListFixtures.peer("AP5R", "Ridge Medic"), Capabilities.MOBILE or Capabilities.TEXT_MESSAGES)
        assertEquals(listOf(PeerVerb.Message, PeerVerb.Ping), PeerVerbs.offered(chat, every))
        // A chat device that also repeats gets Neighbors.
        val both = advertising(chat, Capabilities.TEXT_MESSAGES or Capabilities.REPEATER)
        assertEquals(listOf(PeerVerb.Message, PeerVerb.Ping, PeerVerb.Neighbors), PeerVerbs.offered(both, every))
        val repeater = advertising(ListFixtures.peer("9v", "Spencer Butte"), Capabilities.REPEATER or Capabilities.TELEMETRY, PeerRole.Repeater)
        assertEquals(listOf(PeerVerb.Ping, PeerVerb.Neighbors), PeerVerbs.offered(repeater, every))
        // An advertisement naming nothing leaves Ping alone.
        assertEquals(listOf(PeerVerb.Ping), PeerVerbs.offered(advertising(chat, 0), every))
    }

    @Test
    fun aNodeNeverHeardKeepsEveryVerbLedByIdentify() {
        val unknown = ListFixtures.peer("Hx3m", role = PeerRole.Unknown)
        assertEquals(listOf(PeerVerb.Identify, PeerVerb.Message, PeerVerb.Ping, PeerVerb.Neighbors), PeerVerbs.offered(unknown, every))
        // This build offers every verb (Manage is Phase 4's and not one yet).
        assertEquals(every, PeerVerbs.AVAILABLE)
        // Message needs a stored row.
        assertEquals(listOf(PeerVerb.Identify, PeerVerb.Ping, PeerVerb.Neighbors), PeerVerbs.offered(unknown, PeerVerbs.AVAILABLE, stored = false))
    }

    @Test
    fun theRadioGetsPingAlone() {
        val radio = ListFixtures.peer("Tr4d", companion = true)
        assertEquals(listOf(PeerVerb.Ping), PeerVerbs.offered(radio, every))
        assertEquals(listOf(PeerVerb.Ping), PeerVerbs.offered(radio, PeerVerbs.AVAILABLE))
    }

    @Test
    fun theListRemovesAnyNodeButTheRadio() {
        val saved = ListFixtures.peer("7NQL", "Kestrel")
        val heard = ListFixtures.peer("H1x9", "Fern Ridge", saved = false)
        assertEquals(RemovalChoice.WithConversation(offersRemove = true), RemovalChoice.forList(saved, hasConversation = true))
        assertEquals(RemovalChoice.DeleteOnly, RemovalChoice.forList(saved, hasConversation = false))
        // Not saved, with a conversation: only Delete peer and conversation.
        assertEquals(RemovalChoice.WithConversation(offersRemove = false), RemovalChoice.forList(heard, hasConversation = true))
        assertEquals(RemovalChoice.DeleteOnly, RemovalChoice.forList(heard, hasConversation = false))
        assertNull(RemovalChoice.forList(ListFixtures.peer("Tr4d", companion = true), hasConversation = false))
    }

    @Test
    fun thePageRemovesOnlySavedNodes() {
        val saved = ListFixtures.peer("7NQL", "Kestrel")
        assertEquals(RemovalChoice.WithConversation(offersRemove = true), RemovalChoice.forPage(saved, hasConversation = true))
        assertEquals(RemovalChoice.DeleteOnly, RemovalChoice.forPage(saved, hasConversation = false))
        assertNull(RemovalChoice.forPage(ListFixtures.peer("H1x9", saved = false), hasConversation = true))
        assertNull(RemovalChoice.forPage(ListFixtures.peer("Tr4d", companion = true), hasConversation = false))
    }

    @Test
    fun textMessagesComeFromTheChatRoleOrTheCapability() {
        assertTrue(ListFixtures.peer("A", role = PeerRole.Chat).offersTextMessages)
        assertFalse(ListFixtures.peer("A", role = PeerRole.Repeater).offersTextMessages)
        assertTrue(advertising(ListFixtures.peer("A"), Capabilities.TEXT_MESSAGES, PeerRole.Sensor).offersTextMessages)
        assertFalse(advertising(ListFixtures.peer("A"), Capabilities.TELEMETRY, PeerRole.Sensor).offersTextMessages)
    }

    @Test
    fun distanceIsMeasuredFromThePhoneElseTheRadio() {
        val node = advertising(ListFixtures.peer("AP5R"), 0, latitude = 44.0521, longitude = -123.0868)
        val radio = advertising(ListFixtures.peer("Tr4d", companion = true), 0, latitude = 44.0521, longitude = -123.0368)
        val fromRadio = PeerDistance.of(node, phone = null, radio = radio) { null }!!
        // 0.05° of longitude at 44° north: about 4.0 km, due west.
        assertEquals(4_000.0, fromRadio.meters, 20.0)
        assertEquals(270.0, fromRadio.bearingDegrees, 0.1)
        assertFalse(fromRadio.isUpperBound)
        val phone = PhoneFix(44.0621, -123.0868, accuracyMeters = 5.0, approximate = false)
        val fromPhone = PeerDistance.of(node, phone, radio) { null }!!
        // 0.01° of latitude, south: about 1.1 km.
        assertEquals(1_112.0, fromPhone.meters, 5.0)
        assertEquals(180.0, fromPhone.bearingDegrees, 0.1)
        assertNull(PeerDistance.of(ListFixtures.peer("AP5R"), phone, radio) { null })
        assertNull(PeerDistance.of(node, phone = null, radio = null) { null })
    }

    @Test
    fun cellsCloserThanTheirSizeGiveAnUpperBound() {
        val reference = Reference(44.0, -123.0, cellMeters = 600.0)
        val near = PeerDistance.between(reference, 44.001, -123.0, otherCellMeters = 400.0)
        assertTrue(near.isUpperBound)
        // The centers' 111 m plus half of each cell.
        assertEquals(111.0 + 500.0, near.meters, 2.0)
    }

    @Test
    fun bearingsReadAsTheEightCompassPoints() {
        assertEquals(R.string.compass_north, PeerDistance.compassPoint(359.0))
        assertEquals(R.string.compass_northeast, PeerDistance.compassPoint(40.0))
        assertEquals(R.string.compass_west, PeerDistance.compassPoint(270.0))
        assertEquals(R.string.compass_northwest, PeerDistance.compassPoint(-40.0))
    }
}
