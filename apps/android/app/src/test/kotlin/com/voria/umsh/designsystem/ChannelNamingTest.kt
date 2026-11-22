package com.voria.umsh.designsystem

import com.voria.umsh.models.ChannelKind
import com.voria.umsh.models.ChannelSummary
import com.voria.umsh.models.Octets
import org.junit.Assert.assertEquals
import org.junit.Test

/** The lettering and title rules of `docs/ux/src/apps/channel-badges.md` and `avatars-and-badges.svg` board 3. */
class ChannelNamingTest {
    private fun channel(
        name: String?,
        alias: String? = null,
        canonical: String? = null,
        hex: String = "3f9a",
    ) = ChannelSummary(
        id = "ID",
        kind = if (canonical != null) ChannelKind.Builtin else ChannelKind.PrivateKey,
        canonicalName = canonical,
        name = name,
        alias = alias,
        channelIdHex = hex,
        tint = Octets(byteArrayOf(0x3f, 0x9a.toByte(), 0x10)),
        regionCode = null,
        maxFloodHops = null,
        joinedPhone = true,
        notificationsEnabled = true,
        joinedAtMs = null,
        conversationAddress = null,
    )

    private fun letters(name: String?) = ChannelNaming.lettering(channel(name))
    private fun title(name: String?) = ChannelNaming.title(channel(name))

    @Test
    fun boardThreeRows() {
        assertEquals(listOf("H", "T"), letters("Hot Topic"))
        assertEquals(ChannelTitle.Text("Hot Topic"), title("Hot Topic"))
        assertEquals(listOf("H", "C"), letters("hike-club"))
        assertEquals(ChannelTitle.Text("hike-club"), title("hike-club"))
        assertEquals(listOf("O", "T", "👍🏽", "F"), letters("one two 👍🏽 four five"))
        assertEquals(ChannelTitle.Text("one two 👍🏽 four five"), title("one two 👍🏽 four five"))
        assertEquals(listOf("🔥"), letters("🔥 Hot Topic"))
        assertEquals(ChannelTitle.Text("Hot Topic"), title("🔥 Hot Topic"))
        assertEquals(listOf("3", "F", "9", "A"), letters(null))
        assertEquals(ChannelTitle.Private, title(null))
    }

    @Test
    fun threeAndFourInitialsGoTwoOverTwo() {
        val style = AvatarStyle.channel(letters("one two 👍🏽 four five"), byteArrayOf(1, 2, 3))
        assertEquals(listOf("OT", "👍🏽F"), style.lines)
        assertEquals(listOf("HT"), AvatarStyle.channel(letters("Hot Topic"), byteArrayOf(1, 2, 3)).lines)
        assertEquals(listOf("3F", "9A"), AvatarStyle.channel(letters(null), byteArrayOf(1, 2, 3)).lines)
        assertEquals(0.76f, AvatarStyle.channel(letters("🔥"), byteArrayOf(1, 2, 3)).fontRatio)
    }

    @Test
    fun theChapterExamples() {
        assertEquals(ChannelTitle.Text("Hot"), title("🔥Hot"))
        assertEquals(listOf("🔥"), letters("🔥🎉 Party"))
        assertEquals(ChannelTitle.Text("🎉 Party"), title("🔥🎉 Party"))
        // An emoji-only name: a flag is titled by its region; others keep the
        // name as written until CLDR short names are bundled (design.md D9).
        assertEquals(ChannelTitle.Text("FR"), title("🇫🇷"))
        assertEquals(ChannelTitle.Text("GB-SCT"), title("🏴󠁧󠁢󠁳󠁣󠁴󠁿"))
        assertEquals(ChannelTitle.Text("🔥"), title("🔥"))
        assertEquals(listOf("👌"), letters("👌"))
    }

    @Test
    fun wordsSplitAtWhitespaceHyphensAndUnderscores() {
        assertEquals(listOf("N", "R", "S", "T"), letters("north_ridge-search  team extra"))
        assertEquals(listOf("É", "S"), letters("équipe sud"))
        // Uppercasing is locale-free: a Turkish phone letters the same badge.
        assertEquals(listOf("I"), letters("istanbul"))
        // A text-presentation symbol is not an emoji.
        assertEquals(listOf("©", "M"), letters("© mine"))
        assertEquals(listOf("1️⃣"), letters("1️⃣ first"))
        // Text-default pictographs inside the emoji blocks need the selector too.
        assertEquals(listOf("\uD83C\uDF21", "W"), letters("\uD83C\uDF21 Weather"))
        assertEquals(ChannelTitle.Text("\uD83C\uDF21 Weather"), title("\uD83C\uDF21 Weather"))
        assertEquals(listOf("\uD83C\uDF21\uFE0F"), letters("\uD83C\uDF21\uFE0F Weather"))
        assertEquals(ChannelTitle.Text("Weather"), title("\uD83C\uDF21\uFE0F Weather"))
        assertEquals(listOf("\uD83D\uDEE0", "T"), letters("\uD83D\uDEE0 Tools"))
    }

    /** Unicode spaces break words as iOS's `isWhitespace` does, whatever the regex engine. */
    @Test
    fun noBreakAndIdeographicSpacesSplitWords() {
        assertEquals(listOf("T", "C"), letters("Trail\u00A0Crew"))
        assertEquals(listOf("T", "C"), letters("Trail\u3000Crew"))
        assertEquals(listOf("T", "C"), letters("Trail\u202FCrew"))
    }

    @Test
    fun theStandardChannelsAreFixedUnlessRenamed() {
        assertEquals(ChannelTitle.Public, ChannelNaming.title(channel("public", canonical = "public")))
        assertEquals(listOf("P"), ChannelNaming.lettering(channel("public", canonical = "public")))
        assertEquals(ChannelTitle.Emergency, ChannelNaming.title(channel("EMERGENCY", canonical = "emergency")))
        assertEquals(listOf("E"), ChannelNaming.lettering(channel("EMERGENCY", canonical = "emergency")))
        val renamed = channel("public", alias = "Town square", canonical = "public")
        assertEquals(ChannelTitle.Text("Town square"), ChannelNaming.title(renamed))
        assertEquals(listOf("T", "S"), ChannelNaming.lettering(renamed))
        assertEquals(ChannelNaming.Builtin.Public, ChannelNaming.builtin(renamed))
    }

    @Test
    fun anAliasOutranksTheName() {
        assertEquals(ChannelTitle.Text("Leads"), ChannelNaming.title(channel("Crew Leads", alias = "Leads")))
        assertEquals(ChannelTitle.Text("Crew Leads"), ChannelNaming.title(channel("Crew Leads", alias = " ")))
    }
}
