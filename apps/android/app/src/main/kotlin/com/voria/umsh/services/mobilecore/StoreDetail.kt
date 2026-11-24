package com.voria.umsh.services.mobilecore

import com.voria.umsh.core.MobileStoreException

/**
 * Why a store would not open, as the Storage unavailable screen's detail
 * line says it.
 *
 * Diagnostic text for a bug report, not translated: SQLite's symbolic code
 * and its standard phrase, or the schema versions, plus the file's name.
 */
sealed interface StoreDetail {
    val fileName: String

    /** SQLite would not open the file. */
    data class OpenFailed(override val fileName: String, val code: Int) : StoreDetail

    /** The file is from a newer build, or an older one this build cannot migrate. */
    data class UnsupportedSchema(override val fileName: String, val version: Long) : StoreDetail

    /** SQLite opened it and then failed; a corrupt file arrives here as code 26. */
    data class Failed(override val fileName: String, val code: Int, val detail: String) : StoreDetail

    /** A failure the store does not report at open; kept so nothing is unexplained. */
    data class Other(override val fileName: String, val kind: String) : StoreDetail

    fun render(): String = when (this) {
        is OpenFailed -> "$fileName: ${SqliteCodes.describe(code)}"
        is UnsupportedSchema -> "$fileName: schema v$version, supported v$SUPPORTED_SCHEMA_VERSION"
        is Failed -> "$fileName: ${SqliteCodes.describe(code)}" +
            if (detail.isEmpty() || SqliteCodes.describe(code).endsWith(": $detail")) "" else "; $detail"
        is Other -> "$fileName: $kind"
    }

    companion object {
        /**
         * The schema this build's store creates and reads. Checked against a
         * fresh store by `StoreDetailTest`, so it moves with the core.
         */
        const val SUPPORTED_SCHEMA_VERSION = 33L

        fun from(error: MobileStoreException, fileName: String): StoreDetail = when (error) {
            is MobileStoreException.OpenFailed -> OpenFailed(fileName, error.code)
            is MobileStoreException.UnsupportedSchema -> UnsupportedSchema(fileName, error.version)
            is MobileStoreException.Failed -> Failed(fileName, error.code, error.detail)
            is MobileStoreException.RecordNotFound -> Other(fileName, "RecordNotFound")
            is MobileStoreException.InvalidArgument -> Other(fileName, "InvalidArgument")
        }
    }
}

/** SQLite result codes, named and phrased as `sqlite3_errstr` does. */
internal object SqliteCodes {
    private val primary = mapOf(
        0 to ("SQLITE_OK" to "not an error"),
        1 to ("SQLITE_ERROR" to "SQL logic error"),
        2 to ("SQLITE_INTERNAL" to "internal error"),
        3 to ("SQLITE_PERM" to "access permission denied"),
        4 to ("SQLITE_ABORT" to "query aborted"),
        5 to ("SQLITE_BUSY" to "database is locked"),
        6 to ("SQLITE_LOCKED" to "database table is locked"),
        7 to ("SQLITE_NOMEM" to "out of memory"),
        8 to ("SQLITE_READONLY" to "attempt to write a readonly database"),
        9 to ("SQLITE_INTERRUPT" to "interrupted"),
        10 to ("SQLITE_IOERR" to "disk I/O error"),
        11 to ("SQLITE_CORRUPT" to "database disk image is malformed"),
        12 to ("SQLITE_NOTFOUND" to "unknown operation"),
        13 to ("SQLITE_FULL" to "database or disk is full"),
        14 to ("SQLITE_CANTOPEN" to "unable to open database file"),
        15 to ("SQLITE_PROTOCOL" to "locking protocol"),
        16 to ("SQLITE_EMPTY" to "unknown error"),
        17 to ("SQLITE_SCHEMA" to "database schema has changed"),
        18 to ("SQLITE_TOOBIG" to "string or blob too big"),
        19 to ("SQLITE_CONSTRAINT" to "constraint failed"),
        20 to ("SQLITE_MISMATCH" to "datatype mismatch"),
        21 to ("SQLITE_MISUSE" to "bad parameter or other API misuse"),
        22 to ("SQLITE_NOLFS" to "large file support is disabled"),
        23 to ("SQLITE_AUTH" to "authorization denied"),
        24 to ("SQLITE_FORMAT" to "unknown error"),
        25 to ("SQLITE_RANGE" to "column index out of range"),
        26 to ("SQLITE_NOTADB" to "file is not a database"),
        27 to ("SQLITE_NOTICE" to "notification message"),
        28 to ("SQLITE_WARNING" to "warning message"),
        100 to ("SQLITE_ROW" to "another row available"),
        101 to ("SQLITE_DONE" to "no more rows available"),
    )

    /** `SQLITE_FULL`, or the number when the code has no name. */
    fun name(code: Int): String = primary[code and 0xFF]?.first ?: code.toString()

    /** `SQLITE_NOTADB (26): file is not a database`; an extended code keeps its number. */
    fun describe(code: Int): String {
        val (name, phrase) = primary[code and 0xFF] ?: return "SQLite code $code"
        return "$name ($code): $phrase"
    }
}
