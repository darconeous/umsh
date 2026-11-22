package com.voria.umsh.services.preferences

import androidx.datastore.core.DataStore
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import com.voria.umsh.core.MobileAppPolicyRecord
import com.voria.umsh.services.mobilecore.AppLog
import java.io.File
import java.io.IOException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

/** Where first-run setup stands. */
enum class OnboardingStep { Welcome, ConnectRadio, Done }

/** What a runtime reads from the preferences. */
interface RuntimePreferences {
    /** The policy the core acts on, every time it changes. */
    val policy: Flow<MobileAppPolicyRecord>
    val onboarding: Flow<OnboardingStep>

    suspend fun setOnboarding(step: OnboardingStep)

    suspend fun editPolicy(edit: PolicyPreferences.Editor.() -> Unit)
}

/**
 * The app's preferences: one Preferences DataStore, which must be the only
 * one over its file in the process.
 *
 * Holds what iOS keeps in `UserDefaults`, with the same defaults. Start over
 * clears it with [clear]; the file itself is never deleted under the store.
 */
class AppPreferences(file: File, scope: CoroutineScope) : RuntimePreferences {
    private val store: DataStore<Preferences> = PreferenceDataStoreFactory.create(
        // A damaged file reads as a first launch's, never a crash on every one.
        corruptionHandler = ReplaceFileCorruptionHandler { error ->
            AppLog.e(TAG, "preferences damaged; replaced: ${error.javaClass.simpleName}")
            emptyPreferences()
        },
        scope = scope,
        produceFile = { file },
    )

    /** What is stored, or the defaults while it cannot be read. Writes still throw. */
    private val data: Flow<Preferences> = store.data.catch { error ->
        if (error !is IOException) throw error
        AppLog.e(TAG, "preferences unreadable: ${error.javaClass.simpleName}")
        emit(emptyPreferences())
    }

    override val policy: Flow<MobileAppPolicyRecord> =
        data.map { PolicyPreferences.record(it) }.distinctUntilChanged()

    override val onboarding: Flow<OnboardingStep> = data.map { preferences ->
        // An identity that predates the key has been through setup.
        preferences[ONBOARDING]?.let { name -> OnboardingStep.entries.firstOrNull { it.name == name } }
            ?: OnboardingStep.Done
    }.distinctUntilChanged()

    override suspend fun setOnboarding(step: OnboardingStep) {
        store.edit { it[ONBOARDING] = step.name }
    }

    override suspend fun editPolicy(edit: PolicyPreferences.Editor.() -> Unit) {
        store.edit { PolicyPreferences.Editor(it).edit() }
    }

    /** Debug builds: whether the staging core is the one wanted. */
    val stagingEnabled: Flow<Boolean> = data.map { it[STAGING_ENABLED] ?: false }.distinctUntilChanged()

    suspend fun stagingEnabled(): Boolean = stagingEnabled.first()

    suspend fun setStagingEnabled(enabled: Boolean) {
        store.edit { it[STAGING_ENABLED] = enabled }
    }

    /** Debug builds: the staged radio scans only over Wi-Fi. */
    val stagingWifiScanOnly: Flow<Boolean> =
        data.map { it[STAGING_WIFI_SCAN_ONLY] ?: false }.distinctUntilChanged()

    suspend fun setStagingWifiScanOnly(enabled: Boolean) {
        store.edit { it[STAGING_WIFI_SCAN_ONLY] = enabled }
    }

    /** Debug builds: draw with the fallback scheme instead of dynamic color. */
    val fallbackScheme: Flow<Boolean> = data.map { it[FALLBACK_SCHEME] ?: false }.distinctUntilChanged()

    suspend fun setFallbackScheme(enabled: Boolean) {
        store.edit { it[FALLBACK_SCHEME] = enabled }
    }

    /** Everything, as on a first launch. */
    suspend fun clear() {
        store.edit { it.clear() }
    }

    private companion object {
        const val TAG = "umsh.preferences"
        val ONBOARDING = stringPreferencesKey("onboarding.step")
        val STAGING_ENABLED = booleanPreferencesKey("staging.enabled")
        val STAGING_WIFI_SCAN_ONLY = booleanPreferencesKey("staging.wifiScanOnly")
        val FALLBACK_SCHEME = booleanPreferencesKey("debug.fallbackScheme")
    }
}

/** The policy keys, their defaults (copied from iOS), and the record they make. */
object PolicyPreferences {
    private val ADVERT_INTERVAL = intPreferencesKey("policy.advertIntervalSeconds")
    private val BEACON_INTERVAL = intPreferencesKey("policy.beaconIntervalSeconds")
    private val DISCOVERABLE = booleanPreferencesKey("policy.discoverable")
    private val FLOOD_HOPS = intPreferencesKey("policy.floodHops")
    private val BEACON_FLOOD_HOPS = intPreferencesKey("policy.beaconFloodHops")
    private val SHARE_LOCATION = booleanPreferencesKey("policy.shareLocation")
    private val LOCATION_PRECISION = intPreferencesKey("policy.locationPrecision")
    private val TEST_MESSAGE_ALERTS = booleanPreferencesKey("policy.testMessageAlerts")

    /** Both off: a phone is carried, and announcing it on a timer is a decision. */
    const val DEFAULT_ADVERT_INTERVAL = 0
    const val DEFAULT_BEACON_INTERVAL = 0
    const val DEFAULT_FLOOD_HOPS = 10
    const val DEFAULT_BEACON_FLOOD_HOPS = 5
    const val DEFAULT_LOCATION_PRECISION = 5

    /** What the flood-hop field can carry. */
    private const val MAX_FLOOD_HOPS = 15

    fun record(preferences: Preferences) = MobileAppPolicyRecord(
        advertIntervalSeconds = (preferences[ADVERT_INTERVAL] ?: DEFAULT_ADVERT_INTERVAL).coerceAtLeast(0).toUInt(),
        beaconIntervalSeconds = (preferences[BEACON_INTERVAL] ?: DEFAULT_BEACON_INTERVAL).coerceAtLeast(0).toUInt(),
        discoverable = preferences[DISCOVERABLE] ?: true,
        floodHops = hops(preferences[FLOOD_HOPS], DEFAULT_FLOOD_HOPS),
        beaconFloodHops = hops(preferences[BEACON_FLOOD_HOPS], DEFAULT_BEACON_FLOOD_HOPS),
        locationPrecision = if (preferences[SHARE_LOCATION] == true) {
            (preferences[LOCATION_PRECISION] ?: DEFAULT_LOCATION_PRECISION).coerceIn(0, 255).toUByte()
        } else {
            null
        },
        testMessageAlerts = preferences[TEST_MESSAGE_ALERTS] ?: false,
    )

    /** A stray stored value never makes the core refuse the whole policy. */
    private fun hops(stored: Int?, fallback: Int): UByte =
        (if (stored == null || stored < 0) fallback else stored.coerceAtMost(MAX_FLOOD_HOPS)).toUByte()

    /** Writes to the policy keys, inside one edit. */
    class Editor internal constructor(private val preferences: androidx.datastore.preferences.core.MutablePreferences) {
        var advertIntervalSeconds: Int
            get() = preferences[ADVERT_INTERVAL] ?: DEFAULT_ADVERT_INTERVAL
            set(value) { preferences[ADVERT_INTERVAL] = value }
        var beaconIntervalSeconds: Int
            get() = preferences[BEACON_INTERVAL] ?: DEFAULT_BEACON_INTERVAL
            set(value) { preferences[BEACON_INTERVAL] = value }
        var discoverable: Boolean
            get() = preferences[DISCOVERABLE] ?: true
            set(value) { preferences[DISCOVERABLE] = value }
        var floodHops: Int
            get() = preferences[FLOOD_HOPS] ?: DEFAULT_FLOOD_HOPS
            set(value) { preferences[FLOOD_HOPS] = value }
        var beaconFloodHops: Int
            get() = preferences[BEACON_FLOOD_HOPS] ?: DEFAULT_BEACON_FLOOD_HOPS
            set(value) { preferences[BEACON_FLOOD_HOPS] = value }
        var testMessageAlerts: Boolean
            get() = preferences[TEST_MESSAGE_ALERTS] ?: false
            set(value) { preferences[TEST_MESSAGE_ALERTS] = value }
    }
}
