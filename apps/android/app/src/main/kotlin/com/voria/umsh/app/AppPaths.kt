package com.voria.umsh.app

import android.content.Context
import java.io.File

/**
 * Every file and Keystore alias the app keeps, in one place, so tests can
 * point a whole host at a directory and aliases of their own.
 *
 * What must not be backed up or moved (counters, secrets, the staged air)
 * lives under [noBackupDirectory]; the stores and preferences under
 * [filesDirectory]. Backup is off for both anyway.
 */
data class AppPaths(
    val filesDirectory: File,
    val noBackupDirectory: File,
    /** Prefix of every Keystore alias. */
    val keyAliasPrefix: String = "com.voria.umsh",
) {
    fun store(kind: CoreKind): File = File(
        File(filesDirectory, "umsh"),
        when (kind) {
            CoreKind.Live -> "app.sqlite"
            CoreKind.Staging -> "staging.sqlite"
        },
    )

    /** The store and the files SQLite keeps beside it. */
    fun storeFiles(kind: CoreKind): List<File> {
        val store = store(kind)
        return listOf(store, File(store.path + "-wal"), File(store.path + "-shm"), File(store.path + "-journal"))
    }

    /**
     * Where a core keeps its frame-counter reservations. The live directory
     * never moves: any other restarts this identity's counters, and peers
     * drop its frames as replays.
     */
    fun counters(kind: CoreKind): File = File(
        File(noBackupDirectory, "counters"),
        when (kind) {
            CoreKind.Live -> "live"
            CoreKind.Staging -> "staging"
        },
    )

    fun channelKeys(kind: CoreKind): File = File(
        noBackupDirectory,
        when (kind) {
            CoreKind.Live -> "channel-keys"
            CoreKind.Staging -> "channel-keys-staging"
        },
    )

    fun channelKeyAlias(kind: CoreKind): String = when (kind) {
        CoreKind.Live -> "$keyAliasPrefix.channel-keys"
        CoreKind.Staging -> "$keyAliasPrefix.channel-keys-staging"
    }

    val identity: File get() = File(noBackupDirectory, "identity")
    val identityAlias: String get() = "$keyAliasPrefix.identity"

    /** The staged mesh's own state: its nodes' counters. */
    val stagingAir: File get() = File(noBackupDirectory, "staging-air")

    val preferences: File get() = File(File(filesDirectory, "datastore"), "app.preferences_pb")

    companion object {
        fun of(context: Context) = AppPaths(context.filesDir, context.noBackupFilesDir)
    }
}
