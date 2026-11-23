package com.voria.umsh.features.conversations

import com.voria.umsh.core.MobileRadioPhase
import com.voria.umsh.core.UlcpHostOwnership
import com.voria.umsh.designsystem.Glyphs
import com.voria.umsh.designsystem.MessageSecurity
import com.voria.umsh.designsystem.PeerAvatarShape
import com.voria.umsh.features.conversations.ThreadFixtures.message
import com.voria.umsh.features.conversations.ThreadFixtures.reaction
import com.voria.umsh.models.ChannelKind
import com.voria.umsh.models.MessageRef
import com.voria.umsh.models.NodeHint
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PreviewText.Sender
import com.voria.umsh.models.Quote
import com.voria.umsh.models.ReactionKind
import com.voria.umsh.services.radio.RadioSnapshot
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** The composer's states, reaction chips, links and naming in a thread. */
class ThreadRulesTest {
    private fun radio(phase: MobileRadioPhase, carries: Boolean = phase == MobileRadioPhase.ATTACHED) = RadioSnapshot(
        phase = phase,
        name = "T-Echo",
        linkId = "link",
        host = UlcpHostOwnership.OURS,
        batteryPercent = null,
        batteryMillivolts = null,
        charge = null,
        batteryReadAtMs = null,
        problem = null,
        carriesThisPhone = carries,
    )

    @Test
    fun composerStatesFollowTheRadio() {
        assertEquals(ComposerState.Ready, ComposerState.from(radio(MobileRadioPhase.ATTACHED), known = true))
        // Up but not carrying this phone (another host, or not yet claimed): Send waits, as while connecting.
        assertEquals(ComposerState.Transient, ComposerState.from(radio(MobileRadioPhase.ATTACHED, carries = false), known = true))
        assertEquals(ComposerState.Transient, ComposerState.from(radio(MobileRadioPhase.CONNECTING), known = true))
        assertEquals(ComposerState.Transient, ComposerState.from(radio(MobileRadioPhase.RECONNECTING), known = true))
        // Not read yet is not "no radio".
        assertEquals(ComposerState.Transient, ComposerState.from(null, known = false))
        assertEquals(ComposerState.Blocked, ComposerState.from(null, known = true))
        assertEquals(ComposerState.Blocked, ComposerState.from(radio(MobileRadioPhase.WAITING_FOR_RADIO), known = true))
        assertEquals(ComposerState.Blocked, ComposerState.from(radio(MobileRadioPhase.FAILED), known = true))
    }

    @Test
    fun reactionChipsGroupByGlyphMineFirstAndKeepFailuresApart() {
        val chips = ReactionChip.of(
            listOf(
                reaction(ReactionKind.Heart),
                reaction(ReactionKind.ThumbsUp),
                reaction(ReactionKind.ThumbsUp, mine = true, forwardSecret = true),
                reaction(ReactionKind.ThumbsUp),
                reaction(ReactionKind.Question, mine = true, failed = true),
                reaction(ReactionKind.Other("🔥")),
                reaction(null),
            ),
        )
        assertEquals(
            listOf(
                ReactionChip(Glyphs.THUMBS_UP, 3, ReactionChip.Style.Mine, forwardSecret = true),
                ReactionChip(Glyphs.HEART, 1, ReactionChip.Style.Theirs, forwardSecret = false),
                ReactionChip("🔥", 1, ReactionChip.Style.Theirs, forwardSecret = false),
                ReactionChip(Glyphs.QUESTION, 1, ReactionChip.Style.Failed, forwardSecret = false),
            ),
            chips,
        )
        assertEquals("failed:${Glyphs.QUESTION}", chips.last().key)
    }

    @Test
    fun linksAreFoundAndUmshLinksWin() {
        val body = "See umsh:n:9vXqAbC. or https://umsh.dev/docs, and www.example.org!"
        val links = MessageLink.find(body)
        assertEquals(
            listOf(
                MessageLink.Target.Umsh("umsh:n:9vXqAbC"),
                MessageLink.Target.Web("https://umsh.dev/docs"),
                MessageLink.Target.Web("https://www.example.org"),
            ),
            links.map { it.target },
        )
        assertEquals("umsh:n:9vXqAbC", body.substring(links[0].start, links[0].end))
        assertEquals("plain words", linkified("plain words").text)
        assertEquals(body, linkified(body).text)
        assertEquals(emptyList<MessageLink>(), MessageLink.find("no links here, just umsh: alone"))
    }

    @Test
    fun channelMembersAreNamedByAuthority() {
        val known = ListFixtures.peer("BtC5", advertisedName = "Kestrel", address = "kestrel")
        val unnamed = ListFixtures.peer("7NQL", address = "unnamed")
        val chat = ListFixtures.channelChat(ListFixtures.channel("hike-club"))
        val context = ThreadContext(chat, listOf(known, unnamed).associateBy { it.address }, ListFixtures.names, "", forwardSecret = false)
        val hint = NodeHint(Octets(byteArrayOf(1, 2, 3)), "AP5R")
        assertEquals(Sender.Named("Kestrel"), context.member("kestrel", "Claimed", hint))
        assertEquals(Sender.Named("Claimed"), context.member("unnamed", "Claimed", hint))
        assertEquals(Sender.Hint("7NQL"), context.member("unnamed", null, hint))
        assertEquals(Sender.Hint("AP5R"), context.member(null, " ", hint))
        assertEquals(Sender.Unknown, context.member(null, null, null))
        assertEquals(MessageSecurity.Open, context.security)
        assertEquals(PeerAvatarShape.Circle, context.memberAvatar(message(1, senderAddress = null, senderNodeHint = hint))?.second)
        assertNull(context.memberAvatar(message(1, outbound = true)))
        assertNull(context.runLabel(message(1, outbound = true)))
    }

    @Test
    fun aDirectThreadNamesItsPeerAndQuotes() {
        val peer = ListFixtures.peer("AP5R", advertisedName = "Ridge Medic", address = "ridge")
        val context = ThreadContext(ListFixtures.direct(peer), mapOf("ridge" to peer), ListFixtures.names, "Me", forwardSecret = true)
        assertEquals("Ridge Medic", context.title)
        assertEquals(MessageSecurity.Encrypted, context.security)
        assertEquals(MessageSecurity.ForwardSecret, context.composerSecurity)
        assertEquals(MessageSecurity.ForwardSecret, context.security(message(1, outbound = true, forwardSecret = true)))
        assertNull(context.runLabel(message(1)))
        assertEquals(Sender.Me("Me"), context.statusName(message(1, outbound = true, status = true)))
        assertEquals(Sender.Named("Ridge Medic"), context.statusName(message(1, status = true)))
        assertNull(context.quoteName(Quote.Unavailable))
        val original = Quote.Original(false, MessageRef("s", 1), "Are you at the saddle yet?", false, "ridge", null, null)
        assertEquals(Sender.Named("Ridge Medic"), context.quoteName(original))
        assertEquals(Sender.Me(null), context.quoteName(original.copy(isOutbound = true)))
        val private = ThreadContext(
            ListFixtures.channelChat(ListFixtures.channel("crew", kind = ChannelKind.PrivateKey)),
            emptyMap(),
            ListFixtures.names,
            "",
            forwardSecret = true,
        )
        assertEquals(MessageSecurity.Encrypted, private.composerSecurity)
    }

    @Test
    fun aDraftBegunUnderForwardSecrecyKeepsIt() {
        // Begun while a session is held: secret.
        var secret = settledSecretDraft(wasSecret = false, draftEmpty = false, sessionHeld = true)
        assertEquals(true, secret)
        // The session drops mid-draft: still secret.
        secret = settledSecretDraft(secret, draftEmpty = false, sessionHeld = false)
        assertEquals(true, secret)
        // Erased: it takes what is held again.
        secret = settledSecretDraft(secret, draftEmpty = true, sessionHeld = false)
        assertEquals(false, secret)
        // Begun with no session: not secret, and one arriving later makes it so.
        secret = settledSecretDraft(secret, draftEmpty = false, sessionHeld = false)
        assertEquals(false, secret)
        assertEquals(true, settledSecretDraft(secret, draftEmpty = false, sessionHeld = true))
        // An empty field with a session held: the composer is violet from the session itself.
        assertEquals(false, settledSecretDraft(false, draftEmpty = true, sessionHeld = true))
    }
}
