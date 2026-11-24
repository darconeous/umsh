package com.voria.umsh.app

import com.voria.umsh.app.debug.FakeRadioScanSource
import com.voria.umsh.features.onboarding.RadioScanSource
import com.voria.umsh.services.background.PresenceObservations
import com.voria.umsh.services.location.LocationGrant
import com.voria.umsh.services.location.PhoneFix
import com.voria.umsh.services.location.PhoneLocationSource
import com.voria.umsh.services.radio.RadioLinkFactory
import com.voria.umsh.services.radio.ScriptedRadioLinks
import java.io.File
import java.security.KeyStore
import java.util.UUID
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
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

    /** Nothing observed: the installed app's presence requests are left as they are. */
    override fun presenceObservations(): PresenceObservations = object : PresenceObservations {
        override val available = false

        override fun associationIds(): Collection<String> = emptyList()

        override fun observe(associationId: String, observe: Boolean) = Unit
    }

    /**
     * Share location's grant and readings, set by each test, so no test
     * raises Android's location dialog unasked; the app's own with
     * [realLocation], for the gated runs that answer the system's dialog.
     */
    val testLocation = TestLocationSource()

    @Volatile
    var realLocation = false

    override fun phoneLocationSource(): PhoneLocationSource = if (realLocation) phoneLocation else testLocation

    /** Scripted radios as well as the real links, for states the emulator cannot reach. */
    override fun radioLinks(): RadioLinkFactory = ScriptedRadioLinks(super.radioLinks())

    /**
     * The radio search Connect a radio and Choose a radio use: by default
     * a stand-in that looks and finds nothing, so no test raises Android's
     * Nearby devices dialog unasked. A test sets its own, or [realRadioSearch].
     */
    @Volatile
    var radioSearchFactory: (() -> RadioScanSource)? = null

    override fun radioSearch(offersAssociated: Boolean): RadioScanSource =
        radioSearchFactory?.invoke() ?: FakeRadioScanSource()

    /** The app's own Bluetooth search, for the gated runs against a test peripheral. */
    fun realRadioSearch(offersAssociated: Boolean = false): RadioScanSource = super.radioSearch(offersAssociated)

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
        radioSearchFactory = null
        testLocation.reset()
        realLocation = false
        discard()
        replaceHost(appPaths())
    }

    /** A new host whose runtimes read the app's own location and grant. */
    fun useRealLocation() {
        discard()
        realLocation = true
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

/** A location source a test drives: the grant it shows, and the readings it hands out while listened to. */
class TestLocationSource : PhoneLocationSource {
    override val grant = MutableStateFlow(LocationGrant.None)
    override val inUse = MutableStateFlow(true)
    val readings = MutableSharedFlow<PhoneFix>(replay = 1)

    override fun refresh() = Unit

    override fun fixes(grant: LocationGrant, cellMeters: Double): Flow<PhoneFix> = readings

    /** The last reading handed out, at once: a test with none reads no fix. */
    override suspend fun currentFix(grant: LocationGrant): PhoneFix? = readings.replayCache.lastOrNull()

    fun reset() {
        grant.value = LocationGrant.None
        inUse.value = true
        @OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
        readings.resetReplayCache()
    }
}
