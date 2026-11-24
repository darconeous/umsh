package com.voria.umsh.features.channels

import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** A private channel key never reaches saved state; anything else does as it is. */
class ChannelKeyTextTest {
    private val invitation = "umsh:gk:" + "A".repeat(43)

    @Test
    fun aKeyIsSealedAndOpensOnlyInThisProcess() {
        val sealed = ChannelKeyText.seal(invitation)
        assertFalse(sealed.contains(invitation))
        assertFalse(sealed.contains("A".repeat(43)))
        assertEquals("the same text seals the same way", sealed, ChannelKeyText.seal(invitation))
        assertEquals(invitation, ChannelKeyText.open(sealed))
        // The deprecated spelling, any case, with spaces, and one the core cannot read all hold a key.
        assertTrue(ChannelKeyText.holdsKey("  UMSH:CK:xyz "))
        assertTrue(ChannelKeyText.holdsKey("umsh:gk:not-a-key"))
        assertNotEquals("  UMSH:CK:xyz ", ChannelKeyText.seal("  UMSH:CK:xyz "))
        // A handle from before the process started opens to nothing.
        // (The handle's own form with an ID no seal in this process made.)
        val unknown = sealed.dropLast(36) + UUID.randomUUID()
        assertNotEquals(sealed, unknown)
        assertNull(ChannelKeyText.open(unknown))
    }

    @Test
    fun otherTextIsSavedAsItIs() {
        for (text in listOf("", "hike-club", "umsh:gs:hike-club", "umsh:n:xyz", "Café")) {
            assertFalse(text, ChannelKeyText.holdsKey(text))
            assertEquals(text, ChannelKeyText.seal(text))
            assertEquals(text, ChannelKeyText.open(text))
        }
    }

    @Test
    fun theFieldSaverRestoresAKeyOnlyWhileItIsHeld() {
        val saver = ChannelKeyText.FieldSaver
        val saved = with(saver) { androidx.compose.runtime.saveable.SaverScope { true }.save(invitation) }!!
        assertEquals(invitation, saver.restore(saved))
        assertEquals("", saver.restore("\u0000held:gone"))
        assertEquals("hike-club", with(saver) { androidx.compose.runtime.saveable.SaverScope { true }.save("hike-club") })
    }
}
