package com.voria.umsh.designsystem

import com.voria.umsh.core.renderNodeHint
import com.voria.umsh.models.Capabilities
import com.voria.umsh.models.PeerRole
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Holds [AvatarStyle] and [PeerAvatarShape] to the shared goldens in
 * `docs/ux/src/apps/avatar-goldens.tsv`, which the iOS tests read too, and
 * the hint text to what the core renders.
 */
class AvatarStyleTest {
    private data class Row(
        val kind: String,
        val bytes: ByteArray,
        val role: Int?,
        val caps: Int?,
        val fill: Int,
        val white: Boolean,
        val shape: String,
        val hint: String?,
    )

    private val rows: List<Row> by lazy {
        File(System.getProperty("umsh.repoDir")!!, "docs/ux/src/apps/avatar-goldens.tsv")
            .readLines()
            .filter { it.isNotBlank() && !it.startsWith("#") && !it.startsWith("kind\t") }
            .map { line ->
                val f = line.split('\t')
                Row(
                    kind = f[0].also { require(it == "peer" || it == "channel") { "row kind $it" } },
                    bytes = f[1].chunked(2).map { it.toInt(16).toByte() }.toByteArray(),
                    role = f[2].takeIf { it != "-" }?.toInt(),
                    caps = f[3].takeIf { it != "-" }?.toInt(16),
                    fill = f[4].toInt(16),
                    white = when (f[5]) {
                        "white" -> true
                        "black" -> false
                        else -> error("text color ${f[5]}")
                    },
                    shape = f[6],
                    hint = f[7].takeIf { it != "-" },
                )
            }
    }

    @Test
    fun peerRowsMatchTheGoldens() {
        val peers = rows.filter { it.kind == "peer" }
        assertTrue("goldens hold peer rows", peers.size >= 40)
        for (row in peers) {
            val label = row.bytes.joinToString("") { "%02x".format(it) }
            val style = AvatarStyle.peer(row.bytes, row.hint!!)
            assertEquals("fill $label", row.fill, style.fill)
            assertEquals("text color $label", row.white, style.whiteText)
            val shape = PeerAvatarShape.of(PeerRole.forCode(row.role!!), row.caps?.let(::Capabilities))
            assertEquals("shape $label", row.shape, shape.name.lowercase())
            assertEquals("hint $label", row.hint, renderNodeHint(row.bytes).text)
        }
    }

    @Test
    fun channelRowsMatchTheGoldens() {
        val channels = rows.filter { it.kind == "channel" }
        assertTrue("goldens hold channel rows", channels.size >= 20)
        for (row in channels) {
            val label = row.bytes.joinToString("") { "%02x".format(it) }
            val band = AvatarStyle.channelBand(AvatarStyle.rgbOf(row.bytes))
            assertEquals("fill $label", "%06X".format(row.fill), "%06X".format(band.fill))
            assertEquals("text color $label", row.white, band.whiteText)
        }
    }

    /** The four drawn examples, avatars-and-badges.svg board 1. */
    @Test
    fun theDrawnExamplesLetterTwoOverTwo() {
        fun lines(hex: String) = AvatarStyle.peer(
            hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray(),
            renderNodeHint(hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()).text,
        ).lines
        assertEquals(listOf("Bt", "C5"), lines("a1b203"))
        assertEquals(listOf("9v", "*"), lines("84811b"))
        assertEquals(listOf("7N", "QL"), lines("5ea1b2"))
        assertEquals(listOf("AP", "5R"), lines("8b60f5"))
    }

    @Test
    fun aShortHintIsMidGray() {
        val style = AvatarStyle.peer(byteArrayOf(1, 2), "AB")
        assertEquals(AvatarStyle.MID_GRAY, style.fill)
    }

    @Test
    fun theOwnIdentityAndStoredRolesFollowTheRules() {
        // Repeater capability bit alone is not a triangle; the Chat bit wins over any role.
        assertEquals(PeerAvatarShape.Hexagon, PeerAvatarShape.of(PeerRole.Tracker, Capabilities(Capabilities.REPEATER)))
        assertEquals(PeerAvatarShape.Circle, PeerAvatarShape.of(PeerRole.Repeater, Capabilities(Capabilities.TEXT_MESSAGES)))
        assertEquals(PeerAvatarShape.Triangle, PeerAvatarShape.of(PeerRole.Repeater, null))
        assertEquals(PeerAvatarShape.Circle, PeerAvatarShape.of(PeerRole.Chat, null))
        assertFalse(AvatarStyle.prefersWhiteText(0xFFFFFF))
        assertTrue(AvatarStyle.prefersWhiteText(0x000000))
    }
}
