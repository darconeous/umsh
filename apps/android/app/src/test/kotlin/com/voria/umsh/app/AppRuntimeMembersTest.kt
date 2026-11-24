package com.voria.umsh.app

import com.voria.umsh.models.Octets
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Conversation info and the member sheet over the real core and the staged
 * air (P3k): a channel's notifications, clearing its messages, and asking a
 * member who it is. Nothing goes out on `EMERGENCY`: the core refuses there
 * before anything is sent.
 */
class AppRuntimeMembersTest {
    @get:Rule val temp = TemporaryFolder()

    private lateinit var staged: StagedHost

    @After
    fun tearDown() = runBlocking { staged.close() }

    private suspend fun start(): AppRuntime {
        staged = StagedHost(temp.newFolder())
        val runtime = staged.start()
        staged.stateWhere { state -> state.channelConversations.any { it.channel.name == "Trail Crew" } }
        return runtime
    }

    @Test
    fun aChannelsNotificationsSwitchAndItsMessagesClear() = runBlocking<Unit> {
        val runtime = start()
        val crew = runtime.appState.value!!.channelConversations.first { it.channel.name == "Trail Crew" }
        assertTrue(crew.channel.notificationsEnabled)

        runtime.setChannelNotifications(crew.channel.id, false).await()
        staged.stateWhere { state -> state.channels.first { it.id == crew.channel.id }.notificationsEnabled.not() }
        runtime.setChannelNotifications(crew.channel.id, true).await()
        staged.stateWhere { state -> state.channels.first { it.id == crew.channel.id }.notificationsEnabled }

        // Clear all messages: the history goes, the conversation stays.
        assertTrue(runtime.messageCount(crew.address) > 0)
        runtime.clearMessages(crew.address).await()
        assertEquals(0L, runtime.messageCount(crew.address))
        assertTrue(runtime.appState.value!!.channelConversations.any { it.address == crew.address })
    }

    @Test
    fun aMemberNotSavedAnswersByItsHint() = runBlocking<Unit> {
        val runtime = start()
        val maya = staged.stateWhere { state -> state.peers.any { it.advertisedName == "Maya Ortiz" } }
            .peers.first { it.advertisedName == "Maya Ortiz" }
        // Off Peers: a member the sheet offers Request identity for.
        runtime.demotePeer(maya.address).await()
        val before = staged.stateWhere { state -> state.peers.any { it.address == maya.address && !it.isSaved } }
            .peers.first { it.address == maya.address }.advertisementReceivedAtMs
        val crew = runtime.appState.value!!.channelConversations.first { it.channel.name == "Trail Crew" }
        val sent = staged.messagesWhere(crew.address) { list -> list.any { it.senderAddress == maya.address } }
            .first { it.senderAddress == maya.address }
        val hint = checkNotNull(sent.senderNodeHint).octets
        assertEquals(3, hint.size)

        assertEquals(SendOutcome.Sent, runtime.requestMemberIdentity(crew.address, hint).await())
        staged.stateWhere { state ->
            state.peers.first { it.address == maya.address }.advertisementReceivedAtMs.let { it != null && it != before }
        }
    }

    @Test
    fun emergencyWaitsForItsWarning() = runBlocking<Unit> {
        val runtime = start()
        val emergency = staged.emergency()
        val outcome = runtime.requestMemberIdentity(emergency, Octets(byteArrayOf(1, 2, 3))).await()
        assertTrue("$outcome", outcome is SendOutcome.Refused && outcome.needsEmergencyAgreement)
        assertFalse(outcome is SendOutcome.Sent)
    }
}
