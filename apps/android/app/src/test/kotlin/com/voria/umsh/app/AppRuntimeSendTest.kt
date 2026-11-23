package com.voria.umsh.app

import com.voria.umsh.core.MobileAppException
import com.voria.umsh.core.MobileStagingAirException
import com.voria.umsh.models.DeliveryState
import com.voria.umsh.models.ReactionKind
import com.voria.umsh.models.ResendMode
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The runtime's chat commands over a live core on the staging air: what
 * each answers, and what becomes of the draft. The core's own rules are
 * its tests'; these check the runtime carries them through.
 */
class AppRuntimeSendTest {
    @get:Rule val temp = TemporaryFolder()

    private lateinit var staged: StagedHost

    @After
    fun tearDown() = runBlocking { staged.close() }

    private suspend fun started(): AppRuntime {
        staged = StagedHost(temp.newFolder())
        return staged.start()
    }

    /** A staged peer's direct conversation. */
    private suspend fun direct(runtime: AppRuntime): String =
        staged.stateWhere { it.directConversations.isNotEmpty() }.directConversations.first().address

    @Test
    fun everyVerbGoesOutAndASentMessageClearsItsDraft() = runBlocking<Unit> {
        val runtime = started()
        val address = direct(runtime)
        runtime.saveDraft(address, "Copy that")
        assertEquals(SendOutcome.Sent, runtime.send(address, "Copy that", forwardSecret = null).await())
        val mine = staged.messagesWhere(address) { messages -> messages.any { it.isOutbound && it.body == "Copy that" } }
            .last { it.isOutbound && it.body == "Copy that" }
        // The pause still pending would have written the words back.
        runtime.flushDrafts().await()
        assertEquals("", staged.storedDraft(address))

        assertEquals(SendOutcome.Sent, runtime.reply(address, mine.ref, "And again", forwardSecret = null).await())
        val reply = staged.messagesWhere(address) { messages -> messages.any { it.body == "And again" } }.last { it.body == "And again" }
        assertTrue(reply.quote != null)

        assertTrue(mine.actions.edit)
        assertEquals(SendOutcome.Sent, runtime.edit(address, mine.ref, "Copy that, over").await())
        staged.messagesWhere(address) { messages -> messages.any { it.ref == mine.ref && it.body == "Copy that, over" && it.isEdited } }

        assertEquals(SendOutcome.Sent, runtime.toggleReaction(address, reply.ref, ReactionKind.ThumbsUp).await())
        staged.messagesWhere(address) { messages -> messages.first { it.ref == reply.ref }.reactions.any { it.isMine } }
        assertEquals(SendOutcome.Sent, runtime.react(address, reply.ref, null).await())
        staged.messagesWhere(address) { messages -> messages.first { it.ref == reply.ref }.reactions.none { it.isMine } }

        assertEquals(SendOutcome.Sent, runtime.delete(address, mine.ref).await())
        staged.messagesWhere(address) { messages -> messages.first { it.ref == mine.ref }.isDeleted }
    }

    @Test
    fun aRefusalBeforeTheCoreKeptTheWordsKeepsThemPending() = runBlocking<Unit> {
        val runtime = started()
        direct(runtime)
        // No such conversation: the core refuses before it stores a draft.
        val nowhere = "no-such-conversation"
        runtime.saveDraft(nowhere, "hello")
        val refused = runtime.send(nowhere, "hello", forwardSecret = null).await()
        assertTrue(refused is SendOutcome.Refused)
        assertEquals("hello", runtime.pendingDraft(nowhere))
    }

    @Test
    fun emergencyIsRefusedUntilCertified() = runBlocking<Unit> {
        val runtime = started()
        val emergency = staged.emergency()
        staged.stateWhere { state ->
            state.channelConversations.any { it.address == emergency && it.needsEmergencyAgreement }
        }
        val refused = runtime.send(emergency, "TEST: radio check", forwardSecret = null).await()
        assertTrue((refused as SendOutcome.Refused).needsEmergencyAgreement)
        // A refused message keeps its words as the draft.
        assertEquals("TEST: radio check", staged.storedDraft(emergency))

        runtime.certifyEmergency().getOrThrow()
        staged.stateWhere { state ->
            state.channelConversations.any { it.address == emergency && !it.needsEmergencyAgreement }
        }
        withTimeout(StagedHost.TIMEOUT) { runtime.emergencyCertified.first { it } }
        assertEquals(SendOutcome.Sent, runtime.send(emergency, "TEST: radio check", forwardSecret = null).await())
        assertEquals("", staged.storedDraft(emergency))
    }

    @Test
    fun withoutTheRadioNothingIsSentAndTheWordsStay() = runBlocking<Unit> {
        val runtime = started()
        val address = direct(runtime)
        staged.air.setLinkUp(false)
        staged.carrying(false)
        val refused = runtime.send(address, "Anyone there?", forwardSecret = null).await() as SendOutcome.Refused
        assertTrue(refused.error is MobileAppException.NoRadio || refused.error is MobileAppException.NotThisPhone)
        assertEquals("Anyone there?", staged.storedDraft(address))
        assertTrue(runtime.transcriptNewest(address, 50).messages.none { it.body == "Anyone there?" })
    }

    @Test
    fun aFailedMessageGoesAgainAsTheCoreDecides() = runBlocking<Unit> {
        val runtime = started()
        val address = direct(runtime)
        staged.air.setTransmissionsFailing(true)
        assertEquals(SendOutcome.Sent, runtime.send(address, "Gate code is 4471", forwardSecret = null).await())
        val failed = staged.messagesWhere(address) { messages ->
            messages.any {
                it.body == "Gate code is 4471" &&
                    (it.delivery == DeliveryState.Failed || it.delivery == DeliveryState.Undelivered) &&
                    it.actions.resend != null
            }
        }.last { it.body == "Gate code is 4471" }
        staged.air.setTransmissionsFailing(false)
        // Whatever the dialog offered, the answer says how it went.
        val outcome = runtime.resend(address, failed.ref, forwardSecret = false).await()
        assertTrue(outcome is ResendOutcome.Resent)
        when ((outcome as ResendOutcome.Resent).mode) {
            ResendMode.InPlace -> staged.messagesWhere(address) { messages -> messages.first { it.ref == failed.ref }.delivery != DeliveryState.Undelivered }
            ResendMode.AsNew -> staged.messagesWhere(address) { messages -> messages.none { it.ref == failed.ref } }
        }
        // A second resend of a row no longer failed is refused by the core, not here.
        val again = runtime.resend(address, failed.ref, forwardSecret = false).await()
        assertTrue(again is ResendOutcome.Refused || again is ResendOutcome.Resent)
    }

    @Test
    fun aGapIsAskedFor() = runBlocking<Unit> {
        val runtime = started()
        val channel = staged.stateWhere { state -> state.channelConversations.any { it.channel.name == "Trail Crew" } }
            .channelConversations.first { it.channel.name == "Trail Crew" }.address
        // The staged peer speaks once it has learned the phone.
        withTimeout(StagedHost.TIMEOUT) {
            while (true) {
                try {
                    staged.air.air.peerSaysLosingOne("first", "lost", "last")
                    break
                } catch (_: MobileStagingAirException.NoPhone) {
                    delay(StagedHost.POLL_MS)
                }
            }
        }
        // Once the last has come, its gap waits to be asked for.
        val gap = staged.messagesWhere(channel) { messages ->
            messages.any { it.body == "last" } && messages.any { it.actions.requestMissing }
        }.filter { it.actions.requestMissing }
        assertEquals(SendOutcome.Sent, runtime.requestMissing(channel, gap.map { it.ref }).await())
        staged.messagesWhere(channel) { messages -> messages.any { it.body == "lost" } }
    }
}
