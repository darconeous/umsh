package com.voria.umsh.features.conversations

import com.voria.umsh.models.ChatMessage
import com.voria.umsh.models.MessagePresentation
import com.voria.umsh.models.Presence
import com.voria.umsh.models.TranscriptCursor
import com.voria.umsh.models.TranscriptPage
import com.voria.umsh.models.TranscriptRow

/**
 * The slice of a transcript a thread holds, and what lies beyond it either
 * way (a port of iOS's `TranscriptWindow`). Immutable: every change answers
 * a new window, with its rows derived once rather than on every frame.
 */
data class TranscriptWindow(
    /** Oldest first. */
    val messages: List<ChatMessage> = emptyList(),
    val hasOlder: Boolean = false,
    val hasNewer: Boolean = false,
    /** The transcript revision this window was read at. */
    val loadedRevision: Long = -1,
    val hasLoadedOnce: Boolean = false,
) {
    /** [messages] as display rows. */
    val rows: List<TranscriptRow> = rows(messages, hasOlder)

    /**
     * The newest message of mine, the only one that shows Delivered, Sent or
     * its repeaters. Null while the live edge is not loaded: a message in
     * the middle of history must not read as the latest this phone sent.
     */
    val lastOutboundKey: String? =
        if (hasNewer) null else messages.lastOrNull { it.isOutbound && !it.isDeleted }?.ref?.key

    val oldestCursor: TranscriptCursor? get() = messages.firstOrNull()?.cursor
    val newestCursor: TranscriptCursor? get() = messages.lastOrNull()?.cursor

    /** The window has grown past what it should hold. */
    val exceedsCapacity: Boolean get() = messages.size > CAPACITY

    fun replacedBy(page: TranscriptPage, revision: Long) = TranscriptWindow(
        messages = page.messages,
        hasOlder = page.hasOlder,
        hasNewer = page.hasNewer,
        loadedRevision = revision,
        hasLoadedOnce = true,
    )

    /** A page of older messages onto the front; trimming is [trimmedToCapacity]'s. */
    fun prepending(page: TranscriptPage) = copy(messages = page.messages + messages, hasOlder = page.hasOlder)

    /**
     * The newest messages dropped back to capacity: while reading history
     * the live edge is far below and one tap away, whereas the rows just
     * above the reader are what they are reading.
     */
    fun trimmedToCapacity(): TranscriptWindow {
        val overflow = messages.size - CAPACITY
        if (overflow <= 0) return this
        return copy(messages = messages.dropLast(overflow), hasNewer = true)
    }

    /** A page of newer messages onto the end, the older edge trimmed to capacity. */
    fun appending(page: TranscriptPage): TranscriptWindow {
        val joined = messages + page.messages
        val overflow = joined.size - CAPACITY
        return copy(
            messages = if (overflow > 0) joined.drop(overflow) else joined,
            hasNewer = page.hasNewer,
            hasOlder = hasOlder || overflow > 0,
        )
    }

    companion object {
        /** How many messages open at the live edge, and how many each page toward history adds. */
        const val PAGE_SIZE = 100

        /** The most a window holds before the older edge trims the newer one. */
        const val CAPACITY = 400

        /** How much of a window opened on one message sits either side of it. */
        const val FOCUS_RADIUS = 60

        /** A lull this long gets a date line when the conversation picks up again. */
        const val DATE_LINE_INTERVAL_MS = 3_600_000L

        /**
         * What makes two adjacent messages one utterance; null for a row that
         * interrupts any run (a deletion, an unavailable marker, a status line).
         * The raw hint, not its rendering: a star-truncated rendering can name
         * two hints alike.
         */
        private fun runKey(message: ChatMessage): String? {
            if (message.isDeleted || message.presence == Presence.Unavailable || message.isStatus) return null
            if (message.isOutbound) return "out"
            return message.senderAddress ?: message.senderHint?.let { "hint:${it.hex()}" } ?: "in"
        }

        private val ChatMessage.isGapPlaceholder: Boolean
            get() = presence == Presence.GapPending || presence == Presence.GapIdle

        /** Runs by sender, date lines where the conversation went quiet, and collapsed gaps. */
        fun rows(messages: List<ChatMessage>, hasOlder: Boolean): List<TranscriptRow> {
            val items = ArrayList<TranscriptRow>(messages.size)
            var gap = ArrayList<ChatMessage>()
            var previousMs: Long? = null
            var previousRunKey: String? = null

            fun flushGap() {
                if (gap.isNotEmpty()) {
                    items += TranscriptRow.Gap(gap)
                    previousRunKey = null
                }
                gap = ArrayList()
            }

            for (message in messages) {
                if (message.isGapPlaceholder) {
                    // A placeholder deleted by the engine was filled by an edit: it holds no slot.
                    if (message.isDeleted) continue
                    val last = gap.lastOrNull()
                    if (last != null && last.presence != message.presence) flushGap()
                    gap += message
                    continue
                }
                flushGap()

                val isFirstRow = items.isEmpty()
                val at = message.createdAtMs
                // The window's first message is only the conversation's first
                // when nothing lies behind it.
                val separated = previousMs?.let { at - it >= DATE_LINE_INTERVAL_MS } ?: !hasOlder
                if (separated) items += TranscriptRow.DateLine(message.ref.key, at)

                val key = runKey(message)
                // A date line ends whatever came before it.
                val startsRun = separated || key == null || key != previousRunKey
                val spacing = when {
                    isFirstRow || separated -> 0
                    startsRun -> MessagePresentation.LOOSE_SPACING_DP
                    else -> MessagePresentation.TIGHT_SPACING_DP
                }
                items += TranscriptRow.Message(message, MessagePresentation(isFirstInRun = startsRun, topSpacingDp = spacing))
                previousRunKey = key
                previousMs = at
            }
            flushGap()

            // Closing a run means seeing the row after it.
            for (index in 0 until items.size - 1) {
                val row = items[index] as? TranscriptRow.Message ?: continue
                val next = items[index + 1] as? TranscriptRow.Message ?: continue
                if (!next.presentation.isFirstInRun) {
                    items[index] = row.copy(presentation = row.presentation.copy(isLastInRun = false))
                }
            }
            return items
        }
    }
}
