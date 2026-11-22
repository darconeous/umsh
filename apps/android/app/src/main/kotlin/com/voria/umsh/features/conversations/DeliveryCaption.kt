package com.voria.umsh.features.conversations

import com.voria.umsh.models.ChatMessage
import com.voria.umsh.models.DeliveryState

/**
 * The line under a message (`bubbles.svg` boards 1 and 2), before its words
 * are resolved: text only, never a glyph. Pure, so the JVM tests cover
 * every state.
 */
data class DeliveryCaption(
    /** "Edited", ahead of the rest. */
    val edited: Boolean,
    val state: State?,
) {
    /** The rest of the line: how the message arrived, or how mine is getting on. */
    sealed interface State {
        /** Failures, drawn in the error color. */
        val isFailure: Boolean get() = this == Unconfirmed || this == NotDelivered

        data object ReceivedLate : State
        data object EditOfUnknown : State
        data object Sending : State
        data object Confirming : State
        data object Delivered : State
        data object DeliveredLate : State
        data object DeliveredFlooded : State
        data object Unconfirmed : State
        data object NotDelivered : State

        /** Sent, and how far it was heard repeated. */
        sealed interface Repeat : State
        data object Sent : Repeat

        /** Repeats that named no repeater: counted as repeats, since one repeater may repeat it more than once. */
        data class HeardRepeats(val count: Int) : Repeat

        /** The first repeater that named itself, and how many others were heard. */
        data class SentVia(val lead: RepeaterName, val others: Int) : Repeat
    }

    /** A repeater as a caption names it: a known node's name, else its router hint. */
    sealed interface RepeaterName {
        data class Named(val name: String) : RepeaterName
        data class Hint(val text: String) : RepeaterName
    }

    companion object {
        /**
         * How long after its delivery last moved a direct message names its
         * repeaters before it settles into waiting for its acknowledgment.
         */
        const val REPEAT_SETTLE_MS = 2_000L

        /**
         * [message]'s caption, or null when it has none. Delivered, and Sent
         * or its repeaters where no acknowledgment comes (channels), mark only
         * [isMostRecentOutbound]; everything else shows on every row it
         * applies to. [nameOf] names a repeater's matched peer.
         */
        fun of(
            message: ChatMessage,
            isMostRecentOutbound: Boolean,
            expectsAcknowledgment: Boolean,
            nowMs: Long,
            nameOf: (peerAddress: String) -> String?,
        ): DeliveryCaption? {
            val arrival = when {
                message.isEditOfUnknown -> State.EditOfUnknown
                message.isReceivedLate -> State.ReceivedLate
                else -> null
            }
            val delivery = if (message.isOutbound) delivery(message, isMostRecentOutbound, expectsAcknowledgment, nowMs, nameOf) else null
            // A message is either mine or received: never both lines.
            val state = delivery ?: arrival
            if (!message.isEdited && state == null) return null
            return DeliveryCaption(edited = message.isEdited, state = state)
        }

        /** When [message]'s caption stops naming its repeaters by itself, or null when it is not waiting to. */
        fun settlesAtMs(message: ChatMessage, expectsAcknowledgment: Boolean): Long? {
            if (!message.isOutbound || !expectsAcknowledgment || message.delivery != DeliveryState.Sent) return null
            return message.repeats?.progressAtMs?.plus(REPEAT_SETTLE_MS)
        }

        private fun delivery(
            message: ChatMessage,
            isMostRecentOutbound: Boolean,
            expectsAcknowledgment: Boolean,
            nowMs: Long,
            nameOf: (String) -> String?,
        ): State? = when (message.delivery) {
            null -> null
            DeliveryState.Undelivered -> State.NotDelivered
            DeliveryState.Failed -> State.Unconfirmed
            DeliveryState.Pending -> State.Sending
            DeliveryState.Acknowledged -> when {
                // A recovery, and a route the flood had to find, are worth
                // seeing on every row they happened to.
                message.isDeliveredLate -> State.DeliveredLate
                message.isDeliveredFlooded -> State.DeliveredFlooded
                isMostRecentOutbound -> State.Delivered
                else -> null
            }
            DeliveryState.Sent -> {
                val repeat = repeat(message, nameOf)
                if (expectsAcknowledgment) {
                    // Still waiting: every row says so, first naming who
                    // carried it, then, once that has gone quiet, the wait.
                    val settlesAt = settlesAtMs(message, expectsAcknowledgment)
                    if (settlesAt != null && nowMs < settlesAt) repeat else State.Confirming
                } else if (isMostRecentOutbound) {
                    repeat
                } else {
                    null
                }
            }
        }

        private fun repeat(message: ChatMessage, nameOf: (String) -> String?): State.Repeat {
            val repeats = message.repeats ?: return State.Sent
            val count = repeats.repeaters.size + repeats.anonymous.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
            if (count <= 0) return State.Sent
            val lead = repeats.repeaters.firstOrNull() ?: return State.HeardRepeats(count)
            val name = lead.peerAddress?.let(nameOf)?.takeIf { it.isNotBlank() }
            return State.SentVia(name?.let(RepeaterName::Named) ?: RepeaterName.Hint(lead.text), others = count - 1)
        }
    }
}
