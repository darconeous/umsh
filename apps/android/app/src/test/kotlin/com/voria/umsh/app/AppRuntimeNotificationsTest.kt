package com.voria.umsh.app

import com.voria.umsh.core.MobileNotificationEventRecord
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
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
 * The runtime's half of notifications over a live core on the staging air:
 * what the core asks to be told reaches the one consumer even when it
 * collects late, and a notification's Reply and Mark as read end as iOS's.
 */
class AppRuntimeNotificationsTest {
    @get:Rule val temp = TemporaryFolder()

    private lateinit var staged: StagedHost

    @After
    fun tearDown() = runBlocking { staged.close() }

    private suspend fun started(): AppRuntime {
        staged = StagedHost(temp.newFolder())
        return staged.start()
    }

    private suspend fun direct(): String =
        staged.stateWhere { it.directConversations.isNotEmpty() }.directConversations.first().address

    @Test
    fun whatArrivesBeforeTheNotifierCollectsIsDeliveredNotLost() = runBlocking<Unit> {
        val runtime = started()
        val address = direct()
        // Nothing collects while the peer speaks and the drain runs.
        staged.peerSays("Trail's clear past the second bridge.")
        staged.messagesWhere(address) { messages -> messages.any { !it.isOutbound && it.body == "Trail's clear past the second bridge." } }
        val event = withTimeout(StagedHost.TIMEOUT) {
            while (true) {
                val found = runtime.notificationEvents.receive()
                    .filterIsInstance<MobileNotificationEventRecord.Message>()
                    .firstOrNull { it.body == "Trail's clear past the second bridge." }
                if (found != null) return@withTimeout found
            }
            @Suppress("UNREACHABLE_CODE")
            error("unreachable")
        }
        assertEquals(address, event.conversation)
        assertEquals(null, event.channelId)
    }

    @Test
    fun aReplySendsAndLeavesTheDraftAlone() = runBlocking<Unit> {
        val runtime = started()
        val address = direct()
        runtime.saveDraft(address, "Half a thought")
        runtime.flushDrafts().await()
        assertEquals(ReplyOutcome.Sent, runtime.deliverNotificationReply(address, "On my way").await())
        staged.messagesWhere(address) { messages -> messages.any { it.isOutbound && it.body == "On my way" } }
        assertEquals("Half a thought", staged.storedDraft(address))
    }

    @Test
    fun aReplyWithNoRadioGoesUnderTheDraft() = runBlocking<Unit> {
        val runtime = started()
        val address = direct()
        runtime.saveDraft(address, "Half a thought")
        staged.air.setLinkUp(false)
        staged.carrying(false)
        val addition = async(start = CoroutineStart.UNDISPATCHED) { runtime.draftAdditions.first() }
        val outcome = runtime.deliverNotificationReply(address, "On my way", radioWaitMs = 300).await()
        assertEquals(ReplyOutcome.Failed(savedAsDraft = true), outcome)
        // An open thread is told, so its next save does not write over them.
        assertEquals(DraftAddition(address, "On my way"), withTimeout(StagedHost.TIMEOUT) { addition.await() })
        // The words under the draft that was there, which a pending save did not overwrite.
        assertEquals("Half a thought\nOn my way", staged.storedDraft(address))
        assertTrue(runtime.transcriptNewest(address, 50).messages.none { it.body == "On my way" })
    }

    @Test
    fun aReplyToAConversationNotStoredIsNotKept() = runBlocking<Unit> {
        val runtime = started()
        direct()
        val outcome = runtime.deliverNotificationReply("no-such-conversation", "On my way", radioWaitMs = 300).await()
        assertEquals(ReplyOutcome.Failed(savedAsDraft = false), outcome)
    }

    @Test
    fun markAsReadReadsTheWholeConversation() = runBlocking<Unit> {
        val runtime = started()
        val address = direct()
        staged.peerSays("Are you at the saddle yet?")
        staged.stateWhere { state -> state.directConversations.any { it.address == address && it.unreadCount > 0 } }
        runtime.markReadFromNotification(address).await()
        staged.stateWhere { state -> state.directConversations.any { it.address == address && it.unreadCount == 0L } }
    }
}
