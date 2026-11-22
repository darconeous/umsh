package com.voria.umsh.features.conversations

import com.voria.umsh.features.conversations.DeliveryCaption.RepeaterName
import com.voria.umsh.features.conversations.DeliveryCaption.State
import com.voria.umsh.features.conversations.ThreadFixtures.message
import com.voria.umsh.models.DeliveryState
import com.voria.umsh.models.Octets
import com.voria.umsh.models.Repeats
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** `bubbles.svg` boards 1 and 2: which caption each message shows, and on which rows. */
class DeliveryCaptionTest {
    private val names = mapOf("butte" to "Spencer Butte")

    private fun caption(
        delivery: DeliveryState?,
        newest: Boolean = true,
        direct: Boolean = true,
        nowMs: Long = 10_000,
        repeats: Repeats? = null,
        outbound: Boolean = true,
        edited: Boolean = false,
        deliveredLate: Boolean = false,
        flooded: Boolean = false,
    ) = DeliveryCaption.of(
        message(1, outbound = outbound, delivery = delivery, repeats = repeats, edited = edited,
            deliveredLate = deliveredLate, deliveredFlooded = flooded),
        isMostRecentOutbound = newest,
        expectsAcknowledgment = direct,
        nowMs = nowMs,
        nameOf = names::get,
    )?.let { it.edited to it.state }

    private fun repeater(text: String, peer: String? = null) = Repeats.Repeater(Octets(byteArrayOf(1, 2)), text, peer)

    @Test
    fun everyRowShowsSendingFailuresAndRecoveries() {
        assertEquals(false to State.Sending, caption(DeliveryState.Pending, newest = false))
        assertEquals(false to State.Unconfirmed, caption(DeliveryState.Failed, newest = false))
        assertEquals(false to State.NotDelivered, caption(DeliveryState.Undelivered, newest = false))
        assertEquals(false to State.DeliveredLate, caption(DeliveryState.Acknowledged, newest = false, deliveredLate = true))
        assertEquals(false to State.DeliveredFlooded, caption(DeliveryState.Acknowledged, newest = false, flooded = true))
        assertTrue(State.Unconfirmed.isFailure)
        assertTrue(State.NotDelivered.isFailure)
        assertFalse(State.Sending.isFailure)
    }

    @Test
    fun deliveredAndSentMarkOnlyTheNewestOfMine() {
        assertEquals(false to State.Delivered, caption(DeliveryState.Acknowledged))
        assertNull(caption(DeliveryState.Acknowledged, newest = false))
        assertEquals(false to State.Sent, caption(DeliveryState.Sent, direct = false))
        assertNull(caption(DeliveryState.Sent, direct = false, newest = false))
        assertEquals(true to State.Delivered, caption(DeliveryState.Acknowledged, edited = true))
        assertEquals(true to null, caption(DeliveryState.Acknowledged, edited = true, newest = false))
    }

    @Test
    fun repeatsNameTheFirstRepeaterThatNamedItself() {
        val named = Repeats(listOf(repeater("9v*", "butte"), repeater("7N*")), anonymous = 1, progressAtMs = 0)
        assertEquals(false to State.SentVia(RepeaterName.Named("Spencer Butte"), others = 2), caption(DeliveryState.Sent, direct = false, repeats = named))
        val hinted = Repeats(listOf(repeater("7N*")), anonymous = 0, progressAtMs = 0)
        assertEquals(false to State.SentVia(RepeaterName.Hint("7N*"), others = 0), caption(DeliveryState.Sent, direct = false, repeats = hinted))
        val anonymous = Repeats(emptyList(), anonymous = 3, progressAtMs = 0)
        assertEquals(false to State.HeardRepeats(3), caption(DeliveryState.Sent, direct = false, repeats = anonymous))
    }

    @Test
    fun aDirectMessageNamesItsRepeatersThenWaits() {
        val repeats = Repeats(listOf(repeater("9v*", "butte")), anonymous = 0, progressAtMs = 5_000)
        // Within the settle time: who carried it, on every row.
        assertEquals(
            false to State.SentVia(RepeaterName.Named("Spencer Butte"), others = 0),
            caption(DeliveryState.Sent, newest = false, nowMs = 6_000, repeats = repeats),
        )
        // Then the wait.
        assertEquals(false to State.Confirming, caption(DeliveryState.Sent, newest = false, nowMs = 7_000, repeats = repeats))
        assertEquals(false to State.Confirming, caption(DeliveryState.Sent, newest = false))
        assertEquals(7_000L, DeliveryCaption.settlesAtMs(message(1, outbound = true, delivery = DeliveryState.Sent, repeats = repeats), true))
        assertNull(DeliveryCaption.settlesAtMs(message(1, outbound = true, delivery = DeliveryState.Sent, repeats = repeats), false))
    }

    @Test
    fun receivedMessagesSayHowTheyArrived() {
        assertNull(DeliveryCaption.of(message(1), false, true, 0) { null })
        assertEquals(State.ReceivedLate, DeliveryCaption.of(message(1, receivedLate = true), false, true, 0) { null }?.state)
        assertEquals(State.EditOfUnknown, DeliveryCaption.of(message(1, editOfUnknown = true, receivedLate = true), false, true, 0) { null }?.state)
        assertEquals(DeliveryCaption(edited = true, state = null), DeliveryCaption.of(message(1, edited = true), false, true, 0) { null })
    }
}
