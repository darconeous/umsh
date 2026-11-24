package com.voria.umsh.features.peers

import com.voria.umsh.R
import com.voria.umsh.services.radio.BoardCatalog
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Nearby's names and outlines for each model, from the files the app ships. */
class PlatformCatalogTest {
    private val repo = File(System.getProperty("umsh.repoDir")!!)
    private val boards = BoardCatalog.parse(File(repo, "docs/hardware/boards.json").readText())
    private val catalog = PlatformCatalog.parse(File(repo, "docs/hardware/platforms.json").readText(), boards)

    @Test
    fun everyPlatformHasAnOutlineOtherThanARadios() {
        assertTrue(catalog.platforms.isNotEmpty())
        catalog.platforms.forEach { platform ->
            assertTrue("${platform.id} (${platform.symbol}) is drawn as a host", catalog.model(platform.modelId).glyph != MeetGlyphKind.Board)
        }
        assertEquals(catalog.platforms.size, catalog.platforms.map { it.modelId }.toSet().size)
    }

    @Test
    fun phonesTabletsAndComputers() {
        // The ids Android itself reports (UmshApplication), and iOS's.
        assertEquals(MeetGlyphKind.Phone, catalog.model(0xFE02).glyph)
        assertEquals(MeetGlyphKind.Tablet, catalog.model(0xFE03).glyph)
        assertEquals(MeetGlyphKind.Phone, catalog.model(0xFE00).glyph)
        assertEquals(MeetGlyphKind.Tablet, catalog.model(0xFE01).glyph)
        assertEquals(MeetGlyphKind.Computer, catalog.model(0xFE04).glyph)
        assertEquals(MeetGlyphKind.Computer, catalog.model(0xFE05).glyph)
    }

    @Test
    fun wordsAreResourcesAndProductNamesAreTheFiles() {
        assertEquals(R.string.meet_platform_android_phone, catalog.model(0xFE02).nameRes)
        assertEquals(R.string.meet_platform_android_tablet, catalog.model(0xFE03).nameRes)
        assertEquals(R.string.meet_platform_computer, catalog.model(0xFE05).nameRes)
        val iphone = catalog.model(0xFE00)
        assertNull(iphone.nameRes)
        assertEquals("iPhone", iphone.name)
    }

    @Test
    fun boardsAreRadiosByTheirOwnNames() {
        val pager = catalog.model(9)
        assertEquals(MeetGlyphKind.Board, pager.glyph)
        assertEquals("T-LoRa Pager", pager.name)
        assertNull(pager.nameRes)
        // Unknown to both: a radio with no name, which Nearby calls a device.
        val unknown = catalog.model(0x7777)
        assertEquals(MeetGlyphKind.Board, unknown.glyph)
        assertNull(unknown.name)
        assertNull(unknown.nameRes)
    }

    @Test
    fun anUnknownSymbolIsARadio() {
        assertEquals(MeetGlyphKind.Board, PlatformCatalog.glyph("flipphone"))
        assertEquals(MeetGlyphKind.Tablet, PlatformCatalog.glyph("ipad.landscape"))
    }
}
