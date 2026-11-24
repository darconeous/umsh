package com.voria.umsh.features.conversations

import com.voria.umsh.models.ChatMessage
import com.voria.umsh.models.NodeHint
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.models.PreviewText.Sender

/**
 * The member whose avatar was tapped: their sender hint (the bytes a
 * message claimed), and the rendered node hint when the core gave one.
 * Only this is held while the sheet is open; who they are is read again
 * from the transcript every time it changes ([ChannelMember.of]).
 */
data class MemberRef(val hint: Octets, val nodeHint: NodeHint?)

/**
 * One participant in a channel conversation, as this phone knows them
 * (`conversation-info.svg` 6). Membership is holding the key, so there is no
 * roster: a member is known only once they have said something, and then
 * by the hint their message claimed. An identity reply fills in the
 * address of every message the hint names, so reading the transcript again
 * is what turns an unnamed member into a node while the sheet is open.
 */
data class ChannelMember(
    val hint: Octets,
    val nodeHint: NodeHint?,
    /** The node behind the hint, once this phone knows it. */
    val address: String?,
    /** The name they put on their message: their own claim. */
    val handle: String?,
    /** What the thread calls them, by [ThreadContext.member]'s rule. */
    val name: Sender,
    /** The stored node at [address], saved or not. */
    val peer: PeerSummary?,
) {
    /** A saved node: the sheet leads to its page instead of asking who it is. */
    val savedPeer: PeerSummary? get() = peer?.takeIf { it.isSaved }

    /** The name they call themselves, shown when it is not already the name above. */
    val distinctHandle: String?
        get() = handle?.takeIf { it.isNotBlank() && (name as? Sender.Named)?.name != it }

    companion object {
        /**
         * [ref]'s member among [messages]: any message from the hint will do
         * once an identity has landed, since that fills them all in, but one
         * that names an address is preferred so a straggler stored before it
         * does not hide the answer. With none left in the window, the hint
         * alone, still worth asking about.
         */
        fun of(ref: MemberRef, messages: List<ChatMessage>, context: ThreadContext): ChannelMember {
            val from = messages.filter { !it.isOutbound && it.senderHint == ref.hint }
            val chosen = from.firstOrNull { it.senderAddress != null } ?: from.firstOrNull()
            val nodeHint = chosen?.senderNodeHint ?: ref.nodeHint
            val address = chosen?.senderAddress
            val handle = chosen?.senderHandle
            return ChannelMember(
                hint = ref.hint,
                nodeHint = nodeHint,
                address = address,
                handle = handle,
                name = context.member(address, handle, nodeHint),
                peer = address?.let(context.peers::get),
            )
        }
    }
}
