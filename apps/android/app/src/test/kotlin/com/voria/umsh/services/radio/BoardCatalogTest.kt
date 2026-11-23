package com.voria.umsh.services.radio

import com.voria.umsh.R
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The board list the app ships, and each board's staged photo. */
class BoardCatalogTest {
    private val repo = File(System.getProperty("umsh.repoDir")!!)
    private val catalog = BoardCatalog.parse(File(repo, "docs/hardware/boards.json").readText())

    @Test
    fun everyBoardHasAPhotoStaged() {
        assertTrue(catalog.boards.isNotEmpty())
        val drawables = R.drawable::class.java.fields.map { it.name }.toSet()
        catalog.boards.forEach { board ->
            assertTrue("${board.drawableName} is staged", board.drawableName in drawables)
        }
    }

    @Test
    fun boardsAreFoundByModel() {
        val t1000e = catalog.board(2)
        assertEquals("t1000e", t1000e?.id)
        assertNull(catalog.board(null))
        assertNull(catalog.board(0xFFFF))
        assertEquals(catalog.boards.size, catalog.boards.map { it.modelId }.toSet().size)
    }
}
