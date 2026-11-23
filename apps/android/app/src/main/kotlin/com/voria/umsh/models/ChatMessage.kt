package com.voria.umsh.models

/** A message's durable identity. */
data class MessageRef(val sessionId: String, val handle: Long) {
    /** A key a `LazyColumn` can save in a `Bundle`. */
    val key: String get() = "$sessionId/$handle"
}

/** Where a message sits in its transcript, for paging. */
data class TranscriptCursor(val createdAtMs: Long, val rowId: Long)

enum class DeliveryState { Pending, Sent, Acknowledged, Failed, Undelivered }

/** Whether the message's body is here, or only a placeholder for it. */
enum class Presence { Present, GapPending, GapIdle, Unavailable }

data class Reception(
    val rssiDbm: Int?,
    val snrCentibels: Int?,
    val lqi: Int?,
    val hopCount: Int?,
    /** Two-byte repeater hints, nearest this phone first. */
    val routeHints: List<Octets>,
    val sourceAuthenticated: Boolean,
)

/** A reaction's glyph, as the core parsed its body. */
sealed interface ReactionKind {
    data object Heart : ReactionKind
    data object ThumbsUp : ReactionKind
    data object ThumbsDown : ReactionKind
    data object Laugh : ReactionKind
    data object Exclaim : ReactionKind
    data object Question : ReactionKind
    data class Other(val cluster: String) : ReactionKind
}

data class Reaction(
    val body: String,
    /** Null when the core could not read the body as a reaction. */
    val kind: ReactionKind?,
    val isMine: Boolean,
    val senderAddress: String?,
    val senderHint: Octets?,
    val ref: MessageRef,
    val wireId: Int?,
    val epoch: Int?,
    /** Ours, and its delivery failed outright. */
    val isFailed: Boolean,
    val isForwardSecret: Boolean,
)

/** What a reply quotes. */
sealed interface Quote {
    /** The original is not stored: it never arrived, was dropped, or was lost to a gap. */
    data object Unavailable : Quote

    data class Original(
        val isDeleted: Boolean,
        val target: MessageRef,
        /** Empty when the original was deleted. */
        val body: String,
        val isOutbound: Boolean,
        val senderAddress: String?,
        val senderHandle: String?,
        val senderNodeHint: NodeHint?,
    ) : Quote
}

/** The repeaters heard carrying one of our messages. */
data class Repeats(
    val repeaters: List<Repeater>,
    val anonymous: Long,
    val progressAtMs: Long,
) {
    data class Repeater(
        val hint: Octets,
        /** The core's rendering, else the bytes as lowercase hex. */
        val text: String,
        /** A known peer the core matched the hint to. */
        val peerAddress: String?,
    )
}

/** How a resend of a failed message of mine would first go. */
enum class ResendMode {
    /** As itself, under its own wire ID: "Try again". */
    InPlace,

    /** As a new message that replaces it: "Resend". */
    AsNew,
}

/**
 * What may be done to one message, as the core would take it when it was
 * read (read again once its revise window passes). Copy and Details are
 * always offered; they are the app's own.
 */
data class MessageActions(
    val edit: Boolean = false,
    val delete: Boolean = false,
    /** Null when it cannot be resent. [ResendMode.InPlace] may still end as new. */
    val resend: ResendMode? = null,
    val react: Boolean = false,
    val reply: Boolean = false,
    /** A gap that may be asked for. */
    val requestMissing: Boolean = false,
)

/** One stored message, mapped. */
data class ChatMessage(
    val ref: MessageRef,
    val cursor: TranscriptCursor,
    val body: String,
    val isOutbound: Boolean,
    val delivery: DeliveryState?,
    val isDeleted: Boolean,
    val isEdited: Boolean,
    val wireId: Int?,
    val epoch: Int?,
    val presence: Presence,
    val isReceivedLate: Boolean,
    val isDeliveredLate: Boolean,
    val isDeliveredFlooded: Boolean,
    val isEditOfUnknown: Boolean,
    val isStatus: Boolean,
    val isForwardSecret: Boolean,
    val originalBody: String?,
    val senderAddress: String?,
    val senderHint: Octets?,
    val senderHandle: String?,
    val senderNodeHint: NodeHint?,
    val reception: Reception?,
    val reactions: List<Reaction>,
    val quote: Quote?,
    val repeats: Repeats?,
    val reviseUntilMs: Long?,
    val actions: MessageActions = MessageActions(),
) {
    val createdAtMs: Long get() = cursor.createdAtMs
}

/** One page of a transcript, oldest first. */
data class TranscriptPage(val messages: List<ChatMessage>, val hasOlder: Boolean, val hasNewer: Boolean)
