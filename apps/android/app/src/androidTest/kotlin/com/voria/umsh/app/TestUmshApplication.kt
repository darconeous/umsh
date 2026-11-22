package com.voria.umsh.app

import java.io.File
import java.security.KeyStore
import java.util.UUID
import kotlinx.coroutines.runBlocking

/**
 * The application instrumented tests run under. Its files live in a
 * directory of each test's own and its Keystore aliases carry that test's
 * ID, so no test touches the app's real store or identity, or another
 * test's. [FreshHostRule] gives each test a new host and removes it after.
 * A test that wants staging passes the launch extra, or calls `setStaging`
 * before `ensureRuntime`.
 */
class TestUmshApplication : UmshApplication() {
    /** The current test's files and aliases. */
    @Volatile
    var paths: AppPaths? = null
        private set

    override fun onCreate() {
        // What a run that was killed left behind.
        cacheDir.listFiles { file -> file.name.startsWith(RUN_PREFIX) }?.forEach { it.deleteRecursively() }
        deleteAliases(ALIAS_PREFIX)
        super.onCreate()
    }

    override fun appPaths(): AppPaths {
        val run = UUID.randomUUID().toString()
        val root = File(cacheDir, "$RUN_PREFIX$run")
        return AppPaths(
            filesDirectory = File(root, "files"),
            noBackupDirectory = File(root, "no-backup"),
            keyAliasPrefix = "$ALIAS_PREFIX$run",
        ).also { paths = it }
    }

    /** Before a test: the last host is shut down and removed, and a new one made over new files. */
    fun reset() {
        discard()
        replaceHost(appPaths())
    }

    /** After a test: its host is shut down, and its files and Keystore keys deleted. */
    fun discard() = runBlocking {
        coreHost.shutdown()
        paths?.let { done ->
            done.filesDirectory.parentFile?.deleteRecursively()
            deleteAliases("${done.keyAliasPrefix}.")
        }
        paths = null
    }

    private fun deleteAliases(prefix: String) {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.aliases().toList().filter { it.startsWith(prefix) }.forEach(keyStore::deleteEntry)
    }

    private companion object {
        const val RUN_PREFIX = "test-run-"
        const val ALIAS_PREFIX = "com.voria.umsh.test."
    }
}
