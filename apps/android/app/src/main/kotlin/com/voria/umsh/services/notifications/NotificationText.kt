package com.voria.umsh.services.notifications

import androidx.annotation.PluralsRes
import androidx.annotation.StringRes
import com.voria.umsh.R
import com.voria.umsh.core.MobileNotificationEventRecord
import com.voria.umsh.designsystem.ChannelNaming
import com.voria.umsh.designsystem.Glyphs
import com.voria.umsh.designsystem.Graphemes
import com.voria.umsh.models.AppStateSnapshot
import com.voria.umsh.models.ChannelSummary
import com.voria.umsh.models.DisplayNames
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.services.mobilecore.RecordMapping
import java.util.Locale

/** Words for a notification, before the resources resolve them. */
sealed interface NoteText {
    /** Text as it is: a name, a message. */
    data class Plain(val text: String) : NoteText

    data class Res(@StringRes val id: Int, val args: List<NoteText> = emptyList()) : NoteText

    /** A plural, with its count as the only argument. */
    data class Plural(@PluralsRes val id: Int, val count: Int) : NoteText
}

/** What a notification's icon is drawn from. */
sealed interface NoteAvatar {
    data class Peer(val peer: PeerSummary) : NoteAvatar

    data class Channel(val channel: ChannelSummary) : NoteAvatar

    data object None : NoteAvatar
}

/**
 * One conversation's notification: where it posts, what it is titled, and
 * whether it offers Reply. [group] is a channel's conversation.
 */
data class ConversationSpec(
    val address: String,
    val channel: String,
    val title: NoteText,
    val group: Boolean,
    val offersReply: Boolean,
    val avatar: NoteAvatar,
)

/** Who said a line: [key] is the Person's key, the sender's address when known. */
data class Speaker(val key: String?, val name: NoteText, val avatar: NoteAvatar)

/** What a notice tells; a conversation shows the latest of each, by [id] under its tag. */
enum class NoticeKind(val id: Int) {
    DeliveryFailure(11),
    ReplyFailed(12),
    Heard(13),
}

/** A notification to post, worded. */
sealed interface NotificationPlan {
    /** The conversation this is about; its tag. */
    val address: String

    /** A line added to [spec]'s conversation notification. [status]: a "/me" line, set in italics. */
    data class Line(val spec: ConversationSpec, val speaker: Speaker, val body: NoteText, val status: Boolean) : NotificationPlan {
        override val address: String get() = spec.address
    }

    /** A notice about the conversation, deliberately unlike a message: no style, no Reply. */
    data class Notice(
        override val address: String,
        val kind: NoticeKind,
        val channel: String,
        val title: NoteText,
        val text: NoteText,
        val avatar: NoteAvatar,
    ) : NotificationPlan
}

/** The peers and channels a notification is worded from: one state read's. */
class NotificationDirectory(val peers: Map<String, PeerSummary>, val channels: Map<String, ChannelSummary>) {
    fun peer(address: String?): PeerSummary? = address?.let(peers::get)

    fun channel(id: String?): ChannelSummary? = id?.let { channels[it.uppercase(Locale.ROOT)] }

    /** Whether [event] names a peer or channel this directory does not hold yet. */
    fun misses(event: MobileNotificationEventRecord): Boolean = when (event) {
        is MobileNotificationEventRecord.Message ->
            if (event.channelId != null) channel(event.channelId) == null else peer(event.conversation) == null
        is MobileNotificationEventRecord.Summary ->
            if (event.channelId != null) channel(event.channelId) == null else peer(event.conversation) == null
        is MobileNotificationEventRecord.DeliveryFailure ->
            if (event.channelId != null) channel(event.channelId) == null else peer(event.conversation) == null
        is MobileNotificationEventRecord.PeerHeard -> peer(event.address) == null
    }

    companion object {
        val Empty = NotificationDirectory(emptyMap(), emptyMap())

        fun of(state: AppStateSnapshot?): NotificationDirectory = if (state == null) {
            Empty
        } else {
            NotificationDirectory(
                state.peers.associateBy { it.address },
                state.channels.associateBy { it.id.uppercase(Locale.ROOT) },
            )
        }
    }
}

/**
 * The wording of every notification the core asks for (§6.2), as iOS words
 * them. Which arrivals notify (mutes, silent tests, batching) is the core's
 * call; the words are this side's. Pure, so the JVM tests cover every kind.
 */
object NotificationText {
    /** About one line of a notice before it wraps, once the quotation marks are paid for. */
    const val FAILURE_QUOTE_LIMIT = 36

    /** A reaction has spent a third of the line saying who did what, and wraps rather than clipping to nothing. */
    const val REACTION_QUOTE_LIMIT = 48

    /** The conversation [event] concerns: its notification's tag. */
    fun conversationOf(event: MobileNotificationEventRecord): String = when (event) {
        is MobileNotificationEventRecord.Message -> event.conversation
        is MobileNotificationEventRecord.Summary -> event.conversation
        is MobileNotificationEventRecord.DeliveryFailure -> event.conversation
        is MobileNotificationEventRecord.PeerHeard -> event.address
    }

    fun plan(event: MobileNotificationEventRecord, directory: NotificationDirectory, names: DisplayNames): NotificationPlan =
        when (event) {
            is MobileNotificationEventRecord.Message -> {
                val spec = spec(event.conversation, event.channelId, directory, names, event.senderHandle)
                val speaker = if (event.channelId != null) {
                    val known = directory.peer(event.senderAddress)
                    Speaker(
                        key = event.senderAddress,
                        name = member(known, event.senderHandle, event.senderHint),
                        avatar = known?.let(NoteAvatar::Peer) ?: NoteAvatar.None,
                    )
                } else {
                    Speaker(event.conversation, spec.title, spec.avatar)
                }
                val text = event.reaction?.let { reaction ->
                    val glyph = reaction.reaction?.let { Glyphs.reaction(RecordMapping.reactionKind(it)) } ?: reaction.token
                    NoteText.Res(R.string.notif_reacted, listOf(NoteText.Plain(glyph), quote(reaction.targetBody, REACTION_QUOTE_LIMIT)))
                } ?: NoteText.Plain(event.body)
                if (event.isStatus) {
                    NotificationPlan.Line(spec, speaker, NoteText.Res(R.string.status_line, listOf(speaker.name, text)), status = true)
                } else {
                    NotificationPlan.Line(spec, speaker, text, status = false)
                }
            }
            is MobileNotificationEventRecord.Summary -> {
                val spec = spec(event.conversation, event.channelId, directory, names, null)
                NotificationPlan.Line(
                    spec,
                    Speaker(if (spec.group) null else spec.address, spec.title, spec.avatar),
                    NoteText.Plural(R.plurals.notif_new_messages, event.count.toInt()),
                    status = false,
                )
            }
            is MobileNotificationEventRecord.DeliveryFailure -> {
                val spec = spec(event.conversation, event.channelId, directory, names, null)
                NotificationPlan.Notice(
                    address = event.conversation,
                    kind = NoticeKind.DeliveryFailure,
                    channel = NotificationChannels.PROBLEMS,
                    title = NoteText.Res(
                        if (event.undelivered) R.string.notice_undelivered_title else R.string.notice_unconfirmed_title,
                        listOf(spec.title),
                    ),
                    text = quote(event.body, FAILURE_QUOTE_LIMIT),
                    avatar = spec.avatar,
                )
            }
            is MobileNotificationEventRecord.PeerHeard -> {
                val peer = directory.peer(event.address)
                NotificationPlan.Notice(
                    address = event.address,
                    kind = NoticeKind.Heard,
                    channel = NotificationChannels.DIRECT,
                    title = NoteText.Res(R.string.notice_heard_title, listOf(NoteText.Plain(peer?.let(names::peer) ?: names.unnamedNode))),
                    text = NoteText.Res(R.string.notice_heard_body),
                    avatar = peer?.let(NoteAvatar::Peer) ?: NoteAvatar.None,
                )
            }
        }

    /** A notice that a reply typed into a notification did not go out; [saved] in the draft. */
    fun replyFailed(spec: ConversationSpec?, address: String, saved: Boolean): NotificationPlan.Notice =
        NotificationPlan.Notice(
            address = address,
            kind = NoticeKind.ReplyFailed,
            channel = NotificationChannels.PROBLEMS,
            title = spec?.title ?: NoteText.Res(R.string.app_name),
            text = NoteText.Res(if (saved) R.string.notice_reply_failed else R.string.notice_reply_failed_unsaved),
            avatar = spec?.avatar ?: NoteAvatar.None,
        )

    /**
     * Where a conversation's notification posts and what it is titled. A
     * channel not read yet is titled "New message", as on iOS; a peer not
     * read yet by the name its message carried, else "Unnamed node".
     */
    fun spec(
        address: String,
        channelId: String?,
        directory: NotificationDirectory,
        names: DisplayNames,
        senderHandle: String?,
    ): ConversationSpec {
        if (channelId != null) {
            val channel = directory.channel(channelId)
            val emergency = channel?.canonicalName == ChannelNaming.EMERGENCY
            return ConversationSpec(
                address = address,
                channel = if (emergency) NotificationChannels.EMERGENCY else NotificationChannels.CHANNELS,
                title = channel?.let { NoteText.Plain(names.channel(it)) } ?: NoteText.Res(R.string.notification_public_title),
                group = true,
                // A reply from a notification would skip EMERGENCY's warning,
                // which only the thread shows.
                offersReply = !emergency,
                avatar = channel?.let(NoteAvatar::Channel) ?: NoteAvatar.None,
            )
        }
        val peer = directory.peer(address)
        val name = peer?.let(names::peer) ?: senderHandle?.takeIf { it.isNotBlank() } ?: names.unnamedNode
        return ConversationSpec(
            address = address,
            channel = NotificationChannels.DIRECT,
            title = NoteText.Plain(name),
            group = false,
            offersReply = true,
            avatar = peer?.let(NoteAvatar::Peer) ?: NoteAvatar.None,
        )
    }

    /**
     * A channel member, in descending order of authority: a name this phone
     * holds for them, the name the message carried (unverified, so never
     * above one the phone established), "Member" and their hint, "Member".
     */
    private fun member(peer: PeerSummary?, handle: String?, hint: String?): NoteText {
        peer?.let(DisplayNames::given)?.let { return NoteText.Plain(it) }
        handle?.takeIf { it.isNotBlank() }?.let { return NoteText.Plain(it) }
        val shown = peer?.hint?.text ?: hint
        return if (shown != null) {
            NoteText.Res(R.string.member_hint, listOf(NoteText.Plain(shown)))
        } else {
            NoteText.Res(R.string.member_unknown)
        }
    }

    /**
     * A message as a notification refers to it rather than shows it: one
     * line, in quotation marks, clipped to about [limit] characters. The
     * marks are what tell naming a message from delivering one.
     */
    fun quote(body: String, limit: Int): NoteText {
        val flattened = body.replace('\n', ' ').trim()
        // Counted and cut in whole characters as the reader sees them.
        val clusters = Graphemes.split(flattened)
        if (clusters.size <= limit) {
            return NoteText.Res(R.string.quoted_body, listOf(NoteText.Plain(flattened)))
        }
        val clipped = clusters.take(limit - 1).joinToString("").trimEnd()
        return NoteText.Res(R.string.quoted_body_clipped, listOf(NoteText.Plain(clipped)))
    }
}

/** Whether an event is left unposted (§6.2): the whole rule, since Android has no `willPresent`. */
object NotificationSuppression {
    /**
     * [foreground]: an activity of the app's is resumed. [visible]: the
     * conversation the screen shows. A watched node is always told: it is
     * what the user asked for, whatever is open.
     */
    fun suppressed(event: MobileNotificationEventRecord, foreground: Boolean, visible: String?): Boolean =
        event !is MobileNotificationEventRecord.PeerHeard &&
            foreground && visible != null && visible == NotificationText.conversationOf(event)
}
