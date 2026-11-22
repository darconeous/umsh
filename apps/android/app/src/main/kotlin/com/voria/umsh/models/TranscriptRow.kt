package com.voria.umsh.models

/**
 * How a message sits among its neighbors. A run is a stretch of
 * consecutive messages from one sender with nothing between them, drawn as
 * one utterance: the sender named above its first bubble, their avatar
 * beside its last, the corners between its bubbles joined.
 */
data class MessagePresentation(
    val isFirstInRun: Boolean = true,
    val isLastInRun: Boolean = true,
    /** The space above this row, in dp. */
    val topSpacingDp: Int = LOOSE_SPACING_DP,
) {
    companion object {
        /** Between two separate utterances, and around every row that is not a message. */
        const val LOOSE_SPACING_DP = 10

        /** Between two lines of one utterance. */
        const val TIGHT_SPACING_DP = 2
    }
}

/**
 * A transcript row: a message, the date a lull gave way to, or a run of
 * consecutive gap placeholders in one state, collapsed into one row.
 * [key] is a `LazyColumn` key a `Bundle` can save.
 */
sealed interface TranscriptRow {
    val key: String

    data class Message(val message: ChatMessage, val presentation: MessagePresentation) : TranscriptRow {
        override val key: String get() = message.ref.key
    }

    /** Keyed by the message it introduces, so a page landing above it does not rename it. */
    data class DateLine(val messageKey: String, val atMs: Long) : TranscriptRow {
        override val key: String get() = "date:$messageKey"
    }

    /** Keyed by its newest placeholder: a run straddling the window's older edge keeps its key as history pages in. */
    data class Gap(val messages: List<ChatMessage>) : TranscriptRow {
        override val key: String get() = "gap:${messages.last().ref.key}"

        /** Every placeholder waits for the user to ask for it; otherwise they are being asked for. */
        val isIdle: Boolean get() = messages.first().presence == Presence.GapIdle
    }
}
