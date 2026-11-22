package com.voria.umsh.models

/**
 * A conversation row's second line, before its words are resolved
 * (`conversation-list.svg` board 1). The first that applies wins: an
 * unsent draft, then a deleted last message, none at all, a status line,
 * one of mine, a channel member's, else the body alone.
 */
sealed interface PreviewText {
    data class Draft(val text: String) : PreviewText
    data object Deleted : PreviewText
    data object None : PreviewText

    /** Status text ("/me"): who, then what they say they did, as one line. */
    data class Status(val who: Sender, val body: String) : PreviewText
    data class Mine(val body: String) : PreviewText

    /** A channel message: in a group the body alone does not say who is talking. */
    data class Member(val sender: Sender, val body: String) : PreviewText
    data class Plain(val body: String) : PreviewText

    /** Who a line is from. */
    sealed interface Sender {
        /** This phone, under the name it advertises; "You" while it has none. */
        data class Me(val name: String?) : Sender

        data class Named(val name: String) : Sender

        /** A channel member the phone cannot name: "Member" and its node hint, never a shortened address. */
        data class Hint(val hint: String) : Sender

        /** A sender the record says nothing about. */
        data object Unknown : Sender
    }

    companion object {
        /**
         * [conversation]'s preview. [peers] by address name channel
         * members; [ownName] is this phone's advertised name.
         */
        fun of(
            conversation: ConversationSummary,
            peers: Map<String, PeerSummary>,
            names: DisplayNames,
            ownName: String?,
        ): PreviewText {
            if (conversation.draftText.isNotBlank()) return Draft(oneLine(conversation.draftText))
            val last = conversation.lastMessage ?: return None
            if (last.isDeleted) return Deleted
            val body = oneLine(last.body)
            val sender: Sender? = when {
                last.isOutbound -> Sender.Me(ownName?.takeIf { it.isNotBlank() })
                conversation is ChannelConversationSummary -> member(last, peers)
                conversation is DirectConversationSummary -> Sender.Named(names.peer(conversation.peer))
                else -> null
            }
            return when {
                last.isStatus && sender != null -> Status(sender, body)
                last.isOutbound -> Mine(body)
                conversation is ChannelConversationSummary && sender != null -> Member(sender, body)
                else -> Plain(body)
            }
        }

        /**
         * A channel sender: a known peer's given name, else its node hint,
         * labeled, as the thread names it too (the OD on unnamed senders).
         */
        fun member(preview: ConversationPreview, peers: Map<String, PeerSummary>): Sender {
            val peer = preview.senderAddress?.let(peers::get)
            peer?.let(DisplayNames::given)?.let { return Sender.Named(it) }
            val hint = peer?.hint?.text ?: preview.senderNodeHint?.text
            return if (hint != null) Sender.Hint(hint) else Sender.Unknown
        }

        /** A body on one line: a row shows one, and a line break would cut it at the first. */
        private fun oneLine(text: String): String = text.trim().replace(LINE_BREAKS, " ")

        private val LINE_BREAKS = Regex("\\s*[\\r\\n\\u2028\\u2029]+\\s*")
    }
}
