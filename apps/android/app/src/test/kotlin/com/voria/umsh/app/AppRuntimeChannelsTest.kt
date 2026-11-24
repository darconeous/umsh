package com.voria.umsh.app

import com.voria.umsh.core.MobileAppException
import com.voria.umsh.features.channels.ChannelInputProblem
import com.voria.umsh.features.channels.ChannelJoinViewModel
import com.voria.umsh.features.channels.ChannelLists
import com.voria.umsh.models.ChannelKind
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.flow.first
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

/** Phone-side channels over the real core and the staged air (§4.1 `ChannelsTest`). */
class AppRuntimeChannelsTest {
    @get:Rule val temp = TemporaryFolder()

    private lateinit var staged: StagedHost

    @After
    fun tearDown() = runBlocking { staged.close() }

    private suspend fun start(): AppRuntime {
        staged = StagedHost(temp.newFolder())
        val runtime = staged.start()
        staged.stateWhere { state -> state.channels.any { it.canonicalName == "public" } }
        return runtime
    }

    private suspend fun problemOf(runtime: AppRuntime, input: String): ChannelInputProblem? = try {
        runtime.previewChannel(input)
        null
    } catch (error: MobileAppException) {
        ChannelJoinViewModel.problem(error)
    }

    @Test
    fun createJoinByNameAndByInvitationAlreadyJoinedAndAConflict() = runBlocking<Unit> {
        val runtime = start()

        // New private channel: joined on this phone, under the name given.
        val fire = runtime.createPrivateChannel(" Fire ").await()
        val created = staged.stateWhere { state -> state.channels.any { it.id == fire } }.channels.first { it.id == fire }
        assertEquals(ChannelKind.PrivateKey, created.kind)
        assertEquals("Fire", created.name)
        assertTrue(created.joinedPhone)
        assertNull("a new channel has no conversation until asked", created.conversationAddress)

        // Its invitation carries the key; looking it up finds it joined (board 8).
        val invitation = runtime.channelInvitation(fire).await()
        assertTrue(invitation, invitation.startsWith("umsh:gk:"))
        val again = runtime.previewChannel(invitation)
        assertTrue(again.isPrivate)
        assertTrue(again.alreadyJoined)
        assertEquals(fire, again.existing?.id)
        assertEquals(32, again.key.size)

        // Join by name, with an alias kept on this phone (board 6).
        val byName = runtime.previewChannel("hike-club")
        assertFalse(byName.isPrivate)
        assertEquals("hike-club", byName.canonicalName)
        assertNull(byName.existing)
        val joined = runtime.joinChannel(byName.input, " Hikers ", openConversation = false).await()
        assertNull(joined.conversationAddress)
        val hike = staged.stateWhere { state -> state.channels.any { it.id == joined.channelId } }.channels.first { it.id == joined.channelId }
        assertEquals(ChannelKind.Named, hike.kind)
        assertEquals("Hikers", hike.alias)
        assertTrue(runtime.previewChannel("HIKE-CLUB").alreadyJoined)

        // Update keeps the alias with none given, and clears it when asked.
        runtime.joinChannel("hike-club", null, openConversation = false).await()
        assertEquals("Hikers", runtime.appState.value!!.channels.first { it.id == joined.channelId }.alias)
        runtime.joinChannel("hike-club", null, openConversation = false, clearAlias = true).await()
        assertNull(staged.stateWhere { state -> state.channels.any { it.id == joined.channelId && it.alias == null } }.channels.first { it.id == joined.channelId }.alias)

        // Left, a private channel's key goes; a different channel called the same is a conflict, not the same (board 9).
        runtime.leaveChannel(fire).await()
        staged.stateWhere { state -> state.channels.none { it.id == fire } }
        val other = runtime.createPrivateChannel("fire").await()
        val conflict = runtime.previewChannel(invitation)
        assertNull(conflict.existing)
        assertEquals(other, conflict.nameConflict?.id)
        assertEquals("Fire", conflict.displayName)

        // Joining the invitation again opens its conversation when asked.
        val rejoined = runtime.joinChannel(invitation, null, openConversation = true).await()
        assertNotNull(rejoined.conversationAddress)
        val state = staged.stateWhere { s -> s.channelConversations.any { it.address == rejoined.conversationAddress } }
        assertEquals(2, state.channels.count { it.joinedPhone && it.name.equals("fire", ignoreCase = true) })
    }

    @Test
    fun publicIsLeftAndRejoinedFromTheSuggestions() = runBlocking<Unit> {
        val runtime = start()
        val public = runtime.appState.value!!.channels.first { it.canonicalName == "public" }
        assertTrue(public.joinedPhone)
        assertTrue(ChannelLists.suggested(runtime.appState.value!!.channels).isEmpty())

        runtime.leaveChannel(public.id).await()
        val left = staged.stateWhere { state -> state.channels.any { it.id == public.id && !it.joinedPhone } }
        assertEquals("a built-in channel stays, to be suggested", listOf(public.id), ChannelLists.suggested(left.channels).map { it.id })
        assertTrue(left.channelConversations.none { it.channel.id == public.id })
        // Looking it up by name finds it held, but not joined: a join, not an update.
        val preview = runtime.previewChannel("public")
        assertEquals(public.id, preview.existing?.id)
        assertFalse(preview.alreadyJoined)

        runtime.rejoinChannel(public.id).await()
        val back = staged.stateWhere { state -> state.channels.any { it.id == public.id && it.joinedPhone } }
        assertTrue(ChannelLists.suggested(back.channels).isEmpty())
    }

    @Test
    fun textThatNamesNoChannelSaysWhy() = runBlocking<Unit> {
        val runtime = start()
        assertEquals(ChannelInputProblem.NotAscii, problemOf(runtime, "Café"))
        assertEquals(ChannelInputProblem.TooLong, problemOf(runtime, "a".repeat(65)))
        assertEquals(ChannelInputProblem.NotChannel, problemOf(runtime, "umsh:gk:abc"))
        assertEquals(ChannelInputProblem.NotChannel, problemOf(runtime, "umsh:n:7cQR"))
        assertNull(problemOf(runtime, "a".repeat(64)))
    }

    /**
     * A phone holding as many channels as it can refuses the next, keeping
     * nothing; and joining reaches the staged radio's host channel table when
     * the radio reports one.
     */
    @Test
    fun aFullTableRefusesTheNextAndJoinsReachTheRadio() = runBlocking<Unit> {
        val runtime = start()
        val before = runtime.radio.value?.provisioning?.hostChannelCount
        val joinedBefore = runtime.appState.value!!.channels.count { it.joinedPhone }
        val first = runtime.createPrivateChannel("Ridge SAR").await()
        staged.stateWhere { state -> state.channels.any { it.id == first } }
        if (before != null) {
            withTimeout(StagedHost.TIMEOUT) { runtime.radio.first { it?.provisioning?.hostChannelCount == before + 1 } }
        }
        println("host channel count before=$before joined=$joinedBefore")

        var made = 1
        while (true) {
            try {
                runtime.createPrivateChannel("Channel $made").await()
                made++
            } catch (error: MobileAppException.ChannelTableFull) {
                break
            }
            if (made > 64) fail("never full")
        }
        val full = runtime.reload(full = false).let { it.await(); runtime.appState.value!! }
        val joined = full.channels.count { it.joinedPhone }
        assertEquals("the refused channel is not kept", joinedBefore + made, joined)
        try {
            runtime.joinChannel("ridge-runners", null, openConversation = false).await()
            fail("joined past a full table")
        } catch (_: MobileAppException.ChannelTableFull) {
        }
        assertTrue(runtime.appState.value!!.channels.none { it.canonicalName == "ridge-runners" })
        println("table full at $joined joined channels; host channel count now ${runtime.radio.value?.provisioning?.hostChannelCount}")
    }
}
