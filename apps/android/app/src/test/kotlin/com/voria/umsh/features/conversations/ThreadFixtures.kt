package com.voria.umsh.features.conversations

import com.voria.umsh.models.ChatMessage
import com.voria.umsh.models.DeliveryState
import com.voria.umsh.models.MessageActions
import com.voria.umsh.models.MessageRef
import com.voria.umsh.models.NodeHint
import com.voria.umsh.models.Octets
import com.voria.umsh.models.Presence
import com.voria.umsh.models.Quote
import com.voria.umsh.models.Reaction
import com.voria.umsh.models.ReactionKind
import com.voria.umsh.models.Repeats
import com.voria.umsh.models.TranscriptCursor

/** Hand-built messages for the thread's rules. */
object ThreadFixtures {
    const val MINUTE = 60_000L

    fun message(
        handle: Long,
        at: Long = handle * MINUTE,
        body: String = "message $handle",
        outbound: Boolean = false,
        delivery: DeliveryState? = if (outbound) DeliveryState.Acknowledged else null,
        deleted: Boolean = false,
        edited: Boolean = false,
        status: Boolean = false,
        presence: Presence = Presence.Present,
        senderAddress: String? = if (outbound) null else "peerA",
        senderHint: ByteArray? = null,
        senderHandle: String? = null,
        senderNodeHint: NodeHint? = null,
        receivedLate: Boolean = false,
        deliveredLate: Boolean = false,
        deliveredFlooded: Boolean = false,
        editOfUnknown: Boolean = false,
        forwardSecret: Boolean = false,
        repeats: Repeats? = null,
        reactions: List<Reaction> = emptyList(),
        quote: Quote? = null,
        originalBody: String? = null,
        actions: MessageActions = MessageActions(),
    ) = ChatMessage(
        ref = MessageRef("s", handle),
        cursor = TranscriptCursor(at, handle),
        body = body,
        isOutbound = outbound,
        delivery = delivery,
        isDeleted = deleted,
        isEdited = edited,
        wireId = null,
        epoch = null,
        presence = presence,
        isReceivedLate = receivedLate,
        isDeliveredLate = deliveredLate,
        isDeliveredFlooded = deliveredFlooded,
        isEditOfUnknown = editOfUnknown,
        isStatus = status,
        isForwardSecret = forwardSecret,
        originalBody = originalBody,
        senderAddress = senderAddress,
        senderHint = senderHint?.let(::Octets),
        senderHandle = senderHandle,
        senderNodeHint = senderNodeHint,
        reception = null,
        reactions = reactions,
        quote = quote,
        repeats = repeats,
        reviseUntilMs = null,
        actions = actions,
    )

    fun reaction(
        kind: ReactionKind?,
        mine: Boolean = false,
        failed: Boolean = false,
        forwardSecret: Boolean = false,
        handle: Long = 0,
    ) = Reaction(
        body = "",
        kind = kind,
        isMine = mine,
        senderAddress = null,
        senderHint = null,
        ref = MessageRef("r", handle),
        wireId = null,
        epoch = null,
        isFailed = failed,
        isForwardSecret = forwardSecret,
    )
}
