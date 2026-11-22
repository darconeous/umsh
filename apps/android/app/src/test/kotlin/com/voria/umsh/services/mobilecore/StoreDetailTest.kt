package com.voria.umsh.services.mobilecore

import com.voria.umsh.core.MobileAppStore
import com.voria.umsh.core.MobileStoreException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class StoreDetailTest {
    @get:Rule val temp = TemporaryFolder()

    /** The constant the detail line names is the schema this build's core makes. */
    @Test
    fun supportedSchemaIsTheCoresOwn() {
        MobileAppStore.open(temp.newFolder().resolve("fresh.sqlite").path).use { store ->
            assertEquals(StoreDetail.SUPPORTED_SCHEMA_VERSION, store.schemaVersion())
        }
    }

    @Test
    fun aCorruptFileArrivesAsNotADatabase() {
        val file = temp.newFolder().resolve("app.sqlite")
        file.writeBytes(ByteArray(8192) { (it * 31).toByte() })
        val error = try {
            MobileAppStore.open(file.path).close()
            fail("a corrupt file opened")
            return
        } catch (error: MobileStoreException) {
            error
        }
        val detail = StoreDetail.from(error, file.name)
        assertTrue(detail.toString(), detail is StoreDetail.Failed && detail.code == 26)
        assertTrue(detail.render(), detail.render().startsWith("app.sqlite: SQLITE_NOTADB (26): file is not a database"))
    }

    @Test
    fun rendersEachKind() {
        assertEquals(
            "app.sqlite: SQLITE_CANTOPEN (14): unable to open database file",
            StoreDetail.OpenFailed("app.sqlite", 14).render(),
        )
        assertEquals(
            "app.sqlite: schema v40, supported v${StoreDetail.SUPPORTED_SCHEMA_VERSION}",
            StoreDetail.UnsupportedSchema("app.sqlite", 40).render(),
        )
        // An extended code is named by its primary code and keeps its number.
        assertEquals(
            "app.sqlite: SQLITE_IOERR (266): disk I/O error; short read",
            StoreDetail.Failed("app.sqlite", 266, "short read").render(),
        )
        assertEquals("app.sqlite: SQLite code 999", StoreDetail.OpenFailed("app.sqlite", 999).render())
    }
}
