package com.voria.umsh.services.notifications

import com.voria.umsh.R
import com.voria.umsh.core.MobileNotificationEventRecord
import com.voria.umsh.core.MobileNotificationReactionRecord
import com.voria.umsh.core.MobileReaction
import com.voria.umsh.designsystem.Glyphs
import com.voria.umsh.features.conversations.ListFixtures
import com.voria.umsh.models.AppStateSnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Every event kind the core asks to be told, worded: which resources, which channel, who speaks. */
class NotificationTextTest {
    private val ridge = ListFixtures.peer("AP5R", advertisedName = "Ridge Medic", address = "ridge")
    private val kestrel = ListFixtures.peer("7NQL", alias = "Kestrel", address = "kestrel")
    private val hikers = ListFixtures.channel("Hikers", id = "aaaa-1111")
    private val emergency = ListFixtures.channel(null, id = "eeee-2222", canonical = "emergency")
    private val state: AppStateSnapshot = ListFixtures.state(
        peers = listOf(ridge, kestrel),
        channels = listOf(hikers, emergency),
    )
    private val directory = NotificationDirectory.of(state)
    private val names = ListFixtures.names

    private fun message(
        conversation: String = "ridge",
        channelId: String? = null,
        sender: String? = null,
        handle: String? = null,
        hint: String? = null,
        body: String = "Are you at the saddle yet?",
        status: Boolean = false,
        reaction: MobileNotificationReactionRecord? = null,
    ) = MobileNotificationEventRecord.Message(conversation, channelId, sender, handle, hint, body, status, reaction)

    private fun line(event: MobileNotificationEventRecord) = NotificationText.plan(event, directory, names) as NotificationPlan.Line

    private fun notice(event: MobileNotificationEventRecord) = NotificationText.plan(event, directory, names) as NotificationPlan.Notice

    @Test
    fun aDirectMessageIsTheConversationOfItsPeer() {
        val plan = line(message())
        assertEquals(NotificationChannels.DIRECT, plan.spec.channel)
        assertEquals(NoteText.Plain("Ridge Medic"), plan.spec.title)
        assertFalse(plan.spec.group)
        assertTrue(plan.spec.offersReply)
        assertEquals(NoteAvatar.Peer(ridge), plan.spec.avatar)
        assertEquals(Speaker("ridge", NoteText.Plain("Ridge Medic"), NoteAvatar.Peer(ridge)), plan.speaker)
        assertEquals(NoteText.Plain("Are you at the saddle yet?"), plan.body)
        assertFalse(plan.status)
    }

    @Test
    fun aDirectMessageFromAPeerNotReadYetIsNamedByWhatItCarried() {
        val plan = line(message(conversation = "stranger", handle = "Juniper"))
        assertEquals(NoteText.Plain("Juniper"), plan.spec.title)
        assertEquals(NoteAvatar.None, plan.spec.avatar)
        val unnamed = line(message(conversation = "stranger"))
        assertEquals(NoteText.Plain("Unnamed node"), unnamed.spec.title)
    }

    @Test
    fun aChannelMessageIsAGroupWithEachSenderNamed() {
        val known = line(message(conversation = "ch:aaaa-1111", channelId = "AAAA-1111", sender = "kestrel", handle = "K"))
        assertEquals(NotificationChannels.CHANNELS, known.spec.channel)
        assertTrue(known.spec.group)
        assertEquals(NoteText.Plain("Hikers"), known.spec.title)
        assertEquals(NoteAvatar.Channel(hikers), known.spec.avatar)
        // A name this phone holds beats the one the message carried.
        assertEquals(NoteText.Plain("Kestrel"), known.speaker.name)
        assertEquals(NoteAvatar.Peer(kestrel), known.speaker.avatar)

        val handled = line(message(conversation = "ch:aaaa-1111", channelId = "aaaa-1111", sender = "nobody", handle = "Ana"))
        assertEquals(NoteText.Plain("Ana"), handled.speaker.name)
        assertEquals(NoteAvatar.None, handled.speaker.avatar)

        val hinted = line(message(conversation = "ch:aaaa-1111", channelId = "aaaa-1111", hint = "BtC5"))
        assertEquals(NoteText.Res(R.string.member_hint, listOf(NoteText.Plain("BtC5"))), hinted.speaker.name)

        val unknown = line(message(conversation = "ch:aaaa-1111", channelId = "aaaa-1111"))
        assertEquals(NoteText.Res(R.string.member_unknown), unknown.speaker.name)
    }

    @Test
    fun emergencyPostsInItsOwnChannelWithNoReply() {
        val plan = line(message(conversation = "ch:eeee-2222", channelId = "eeee-2222", handle = "Ana"))
        assertEquals(NotificationChannels.EMERGENCY, plan.spec.channel)
        assertFalse(plan.spec.offersReply)
        assertEquals(NoteText.Plain("EMERGENCY"), plan.spec.title)
    }

    @Test
    fun aChannelNotReadYetIsANewMessage() {
        val plan = line(message(conversation = "ch:zzzz", channelId = "zzzz"))
        assertEquals(NotificationChannels.CHANNELS, plan.spec.channel)
        assertEquals(NoteText.Res(R.string.notification_public_title), plan.spec.title)
        assertTrue(plan.spec.offersReply)
    }

    @Test
    fun aStatusLineOpensWithItsSender() {
        val plan = line(message(body = "is at the saddle", status = true))
        assertTrue(plan.status)
        assertEquals(
            NoteText.Res(R.string.status_line, listOf(NoteText.Plain("Ridge Medic"), NoteText.Plain("is at the saddle"))),
            plan.body,
        )
    }

    @Test
    fun aReactionIsSaidWithItsGlyphAndTheMessageQuoted() {
        val reaction = MobileNotificationReactionRecord("+1", MobileReaction.ThumbsUp, "Copy, heading up now.")
        val plan = line(message(body = "+1", reaction = reaction))
        assertEquals(
            NoteText.Res(
                R.string.notif_reacted,
                listOf(
                    NoteText.Plain(Glyphs.THUMBS_UP),
                    NoteText.Res(R.string.quoted_body, listOf(NoteText.Plain("Copy, heading up now."))),
                ),
            ),
            plan.body,
        )
        // A token that reads as nothing is shown as sent.
        val bare = line(message(body = "~", reaction = MobileNotificationReactionRecord("~", null, "Hi")))
        assertEquals(NoteText.Plain("~"), (bare.body as NoteText.Res).args.first())
    }

    @Test
    fun severalArrivalsAreCountedWithAPlural() {
        val direct = line(MobileNotificationEventRecord.Summary("ridge", null, 16u))
        assertEquals(NoteText.Plural(R.plurals.notif_new_messages, 16), direct.body)
        assertEquals("ridge", direct.speaker.key)
        val channel = line(MobileNotificationEventRecord.Summary("ch:aaaa-1111", "aaaa-1111", 3u))
        assertEquals(NoteText.Plural(R.plurals.notif_new_messages, 3), channel.body)
        assertEquals(NoteText.Plain("Hikers"), channel.speaker.name)
    }

    @Test
    fun aDeliveryFailureIsANoticeQuotingTheMessage() {
        val unconfirmed = notice(MobileNotificationEventRecord.DeliveryFailure("ridge", null, "Copy, heading up now.", false))
        assertEquals(NotificationChannels.PROBLEMS, unconfirmed.channel)
        assertEquals(NoteText.Res(R.string.notice_unconfirmed_title, listOf(NoteText.Plain("Ridge Medic"))), unconfirmed.title)
        assertEquals(NoteText.Res(R.string.quoted_body, listOf(NoteText.Plain("Copy, heading up now."))), unconfirmed.text)
        assertEquals(NoteAvatar.Peer(ridge), unconfirmed.avatar)

        val undelivered = notice(MobileNotificationEventRecord.DeliveryFailure("kestrel", null, "Thanks! Got it.", true))
        assertEquals(NoteText.Res(R.string.notice_undelivered_title, listOf(NoteText.Plain("Kestrel"))), undelivered.title)

        val onChannel = notice(MobileNotificationEventRecord.DeliveryFailure("ch:aaaa-1111", "aaaa-1111", "hi", true))
        assertEquals(NoteText.Res(R.string.notice_undelivered_title, listOf(NoteText.Plain("Hikers"))), onChannel.title)
    }

    @Test
    fun aWatchedNodeIsOnTheAir() {
        val heard = notice(MobileNotificationEventRecord.PeerHeard("kestrel"))
        assertEquals(NotificationChannels.DIRECT, heard.channel)
        assertEquals(NoteText.Res(R.string.notice_heard_title, listOf(NoteText.Plain("Kestrel"))), heard.title)
        assertEquals(NoteText.Res(R.string.notice_heard_body), heard.text)
        assertEquals("kestrel", heard.address)
    }

    @Test
    fun aReplyThatFailedSaysWhetherItWasKept() {
        val spec = NotificationText.spec("ridge", null, directory, names, null)
        assertEquals(NoteText.Res(R.string.notice_reply_failed), NotificationText.replyFailed(spec, "ridge", saved = true).text)
        assertEquals(NoteText.Res(R.string.notice_reply_failed_unsaved), NotificationText.replyFailed(spec, "ridge", saved = false).text)
        assertEquals(NoteText.Plain("Ridge Medic"), NotificationText.replyFailed(spec, "ridge", saved = true).title)
        assertEquals(NoteText.Res(R.string.app_name), NotificationText.replyFailed(null, "ridge", saved = false).title)
    }

    @Test
    fun aQuoteIsOneLineClippedInWholeCharacters() {
        assertEquals(NoteText.Res(R.string.quoted_body, listOf(NoteText.Plain("a b"))), NotificationText.quote(" a\nb ", 36))
        val long = "x".repeat(40)
        assertEquals(
            NoteText.Res(R.string.quoted_body_clipped, listOf(NoteText.Plain("x".repeat(35)))),
            NotificationText.quote(long, 36),
        )
        // A flag is one character, never cut in half.
        val flags = "🇫🇷".repeat(5)
        val clipped = NotificationText.quote(flags, 3) as NoteText.Res
        assertEquals(NoteText.Plain("🇫🇷🇫🇷"), clipped.args.single())
    }

    @Test
    fun aMissingNameIsReadBeforeTheWords() {
        assertFalse(directory.misses(message()))
        assertTrue(directory.misses(message(conversation = "stranger")))
        assertTrue(directory.misses(message(conversation = "ch:zzzz", channelId = "zzzz")))
        assertFalse(directory.misses(MobileNotificationEventRecord.Summary("ch:aaaa-1111", "AAAA-1111", 2u)))
    }
}
