package com.voria.umsh.app

import com.voria.umsh.models.ChatMessage
import com.voria.umsh.models.DeliveryState
import com.voria.umsh.models.MessageRef
import com.voria.umsh.models.Presence
import com.voria.umsh.models.TranscriptCursor
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** D8: each delivery change of a message sent is logged with its time since the send, until it settles. */
class SendTimingsTest {
    private val lines = mutableListOf<String>()
    private val timings = SendTimings { lines += it }

    private fun message(handle: Long, delivery: DeliveryState?, outbound: Boolean = true) = ChatMessage(
        ref = MessageRef("s", handle), cursor = TranscriptCursor(handle, handle), body = "hi", isOutbound = outbound,
        delivery = delivery, isDeleted = false, isEdited = false, wireId = null, epoch = null, presence = Presence.Present,
        isReceivedLate = false, isDeliveredLate = false, isDeliveredFlooded = false, isEditOfUnknown = false, isStatus = false,
        isForwardSecret = false, originalBody = null, senderAddress = null, senderHint = null, senderHandle = null,
        senderNodeHint = null, reception = null, reactions = emptyList(), quote = null, repeats = null, reviseUntilMs = null,
    )

    @Test
    fun eachChangeIsLoggedUntilItSettles() {
        timings.sent("a", 1_000, listOf(message(1, DeliveryState.Acknowledged), message(2, DeliveryState.Pending), message(3, null, outbound = false)), 1_050)
        assertEquals(setOf("a"), timings.addresses())
        timings.changed("a", listOf(message(2, DeliveryState.Pending)), 1_100)
        assertTrue(lines.isEmpty())
        timings.changed("a", listOf(message(2, DeliveryState.Sent)), 1_400)
        timings.changed("a", listOf(message(2, DeliveryState.Acknowledged)), 3_000)
        assertEquals(listOf("send timing: Pending → Sent after 400 ms", "send timing: Sent → Acknowledged after 2000 ms"), lines)
        assertTrue(timings.addresses().isEmpty())
    }

    @Test
    fun aMessageIsWatchedForTenMinutesAtMost() {
        timings.sent("a", 0, listOf(message(2, DeliveryState.Pending)), 10)
        timings.changed("a", listOf(message(2, DeliveryState.Pending)), SendTimings.WATCH_MS + 1)
        assertTrue(timings.addresses().isEmpty())
        assertEquals(1, lines.size)
    }

    /** The read after the send came late (Doze): a change before it is logged at the read, from the send. */
    @Test
    fun aChangeBeforeTheFirstReadIsLoggedThere() {
        timings.sent("a", 1_000, listOf(message(2, DeliveryState.Sent)), 1_700)
        assertEquals(listOf("send timing: Pending → Sent by 700 ms (first read)"), lines)
        timings.changed("a", listOf(message(2, DeliveryState.Acknowledged)), 2_000)
        assertEquals("send timing: Sent → Acknowledged after 1000 ms", lines.last())
        assertTrue(timings.addresses().isEmpty())
    }

    /** Settled before the first read: logged once there, and never watched. */
    @Test
    fun aMessageSettledByTheFirstReadIsNotWatched() {
        timings.sent("a", 1_000, listOf(message(2, DeliveryState.Acknowledged)), 1_900)
        assertEquals(listOf("send timing: Pending → Acknowledged by 900 ms (first read)"), lines)
        assertTrue(timings.addresses().isEmpty())
    }
}
