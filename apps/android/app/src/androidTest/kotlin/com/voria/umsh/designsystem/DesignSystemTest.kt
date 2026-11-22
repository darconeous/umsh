package com.voria.umsh.designsystem

import android.content.ClipboardManager
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertHeightIsAtLeast
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.text.VerbatimTtsAnnotation
import androidx.compose.ui.unit.dp
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.models.ChannelKind
import com.voria.umsh.models.ChannelSummary
import com.voria.umsh.models.NodeHint
import com.voria.umsh.models.Octets
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** The design system's spoken text and dialog wiring, on a device. */
class DesignSystemTest {
    @get:Rule val compose = createComposeRule()

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private val ap5r = NodeHint(Octets(byteArrayOf(0x8b.toByte(), 0x60, 0xf5.toByte())), "AP5R")

    @Test
    fun anAvatarSpellsItsHint() {
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                PeerAvatar(ap5r, PeerAvatarShape.Circle, Modifier.testTag("plain"))
                PeerAvatar(ap5r, PeerAvatarShape.Circle, Modifier.testTag("favorite"), favorite = true)
            }
        }
        val plain = compose.onNodeWithTag("plain").fetchSemanticsNode().config[SemanticsProperties.Text].single()
        assertEquals("Node hint ⁦AP5R⁩", plain.text)
        val spelled = plain.getTtsAnnotations(0, plain.length).single().item
        assertEquals(VerbatimTtsAnnotation("AP5R"), spelled)
        val favorite = compose.onNodeWithTag("favorite").fetchSemanticsNode().config[SemanticsProperties.Text].single()
        assertEquals("Favorite node, hint ⁦AP5R⁩", favorite.text)
    }

    @Test
    fun aMergedRowSilencesTheAvatar() {
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                PeerAvatar(ap5r, PeerAvatarShape.Circle, Modifier.testTag("quiet"), describe = false)
            }
        }
        val config = compose.onNodeWithTag("quiet").fetchSemanticsNode().config
        assertEquals(null, config.getOrNull(SemanticsProperties.Text))
        assertEquals(null, config.getOrNull(SemanticsProperties.ContentDescription))
    }

    @Test
    fun aBadgeNamesItsChannelByTitle() {
        val channel = ChannelSummary(
            id = "ID", kind = ChannelKind.Named, canonicalName = null, name = "🔥 Hot Topic", alias = null,
            channelIdHex = "5b2a", tint = Octets(byteArrayOf(0x5b, 0x2a, 0x86.toByte())), regionCode = null,
            maxFloodHops = null, joinedPhone = true, notificationsEnabled = true, joinedAtMs = null,
            conversationAddress = null,
        )
        compose.setContent { UmshTheme(fallbackScheme = true) { ChannelBadge(channel, Modifier.testTag("badge")) } }
        compose.onNodeWithTag("badge").assert(
            SemanticsMatcher.expectValue(
                SemanticsProperties.ContentDescription,
                listOf(context.getString(R.string.channel_badge, "Hot Topic")),
            ),
        )
    }

    @Test
    fun aNeverNamedBadgeSpellsItsIdentifier() {
        val channel = channel(kind = ChannelKind.PrivateKey, name = null, idHex = "3f9a")
        compose.setContent { UmshTheme(fallbackScheme = true) { ChannelBadge(channel, Modifier.testTag("badge")) } }
        val spoken = compose.onNodeWithTag("badge").fetchSemanticsNode().config[SemanticsProperties.Text].single()
        assertEquals(context.getString(R.string.channel_badge_private, "\u2066" + "3F9A\u2069"), spoken.text)
        assertEquals(VerbatimTtsAnnotation("3F9A"), spoken.getTtsAnnotations(0, spoken.length).single().item)
    }

    @Test
    fun theAddressIsAFullSizeTarget() {
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                CanonicalAddress("Ju8QmN2rT5vXbC7kLpZ4wYhD9sFgE3aRtUiKqP6nM1xW", Modifier.testTag("address"))
            }
        }
        compose.onNodeWithTag("address").assertHeightIsAtLeast(48.dp)
    }

    @Test
    fun theFailureDialogOffersCopyAndOkOnly() {
        var dismissed = false
        val words = listOf("Title", "Body", "Reason", "DETAILS")
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                FailureDialog(words[0], words[1], words[2], words[3], onDismiss = { dismissed = true })
            }
        }
        compose.onNodeWithTag(Tags.FAILURE_DIALOG).assertIsDisplayed()
        // Two actions, and no third (no retry).
        val actions = compose.onAllNodes(hasClickAction() and hasAnyAncestor(hasTestTag(Tags.FAILURE_DIALOG)))
        actions.assertCountEquals(2)
        actions[0].assert(hasTestTag(Tags.FAILURE_COPY_DETAILS) or hasTestTag(Tags.FAILURE_OK))
        actions[1].assert(hasTestTag(Tags.FAILURE_COPY_DETAILS) or hasTestTag(Tags.FAILURE_OK))

        compose.onNodeWithTag(Tags.FAILURE_COPY_DETAILS).performClick()
        compose.waitForIdle()
        val clipboard = InstrumentationRegistry.getInstrumentation().targetContext
            .getSystemService(ClipboardManager::class.java)
        assertEquals("DETAILS", clipboard.primaryClip?.getItemAt(0)?.text?.toString())
        assertTrue(!dismissed)
        compose.onNodeWithTag(Tags.FAILURE_OK).performClick()
        assertTrue(dismissed)
    }

    private fun channel(kind: ChannelKind, name: String?, idHex: String) = ChannelSummary(
        id = "ID", kind = kind, canonicalName = null, name = name, alias = null,
        channelIdHex = idHex, tint = Octets(byteArrayOf(0x3f, 0x9a.toByte(), 0x10)), regionCode = null,
        maxFloodHops = null, joinedPhone = true, notificationsEnabled = true, joinedAtMs = null,
        conversationAddress = null,
    )
}
