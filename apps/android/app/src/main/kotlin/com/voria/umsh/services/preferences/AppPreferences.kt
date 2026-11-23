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
import com.voria.umsh.services.background.ReconnectStrategy
import com.voria.umsh.services.mobilecore.AppLog
import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.PendingBinding
import com.voria.umsh.services.radio.RadioKind
import com.voria.umsh.services.radio.RadioRegistry
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

    /**
     * Debug builds: what follows the reconnect window (D7). Presence unless
     * the Developer switch chose Waiting; release builds never write it.
     */
    val reconnectStrategy: Flow<ReconnectStrategy> = data.map { preferences ->
        ReconnectStrategy.entries.firstOrNull { it.name == preferences[RECONNECT_STRATEGY] } ?: ReconnectStrategy.Presence
    }.distinctUntilChanged()

    suspend fun setReconnectStrategy(strategy: ReconnectStrategy) {
        store.edit { it[RECONNECT_STRATEGY] = strategy.name }
    }

    /**
     * Android has stopped showing its Nearby devices dialog, as the last
     * request's result showed: Allow opens the app's settings instead.
     */
    val nearbyDevicesBlocked: Flow<Boolean> = data.map { it[NEARBY_BLOCKED] ?: false }.distinctUntilChanged()

    suspend fun setNearbyDevicesBlocked(blocked: Boolean) {
        store.edit { it[NEARBY_BLOCKED] = blocked }
    }

    /**
     * Hide contents on the lock screen (D10): a message notification posted
     * while the phone is locked shows only its public version until unlock.
     */
    val hideLockScreenContents: Flow<Boolean> = data.map { it[HIDE_LOCK_SCREEN] ?: false }.distinctUntilChanged()

    suspend fun setHideLockScreenContents(hide: Boolean) {
        store.edit { it[HIDE_LOCK_SCREEN] = hide }
    }

    /** Android has stopped showing its location dialog: Allow opens the app's settings. */
    val locationBlocked: Flow<Boolean> = data.map { it[LOCATION_BLOCKED] ?: false }.distinctUntilChanged()

    suspend fun setLocationBlocked(blocked: Boolean) {
        store.edit { it[LOCATION_BLOCKED] = blocked }
    }

    /** Android has stopped offering precise location over an approximate grant. */
    val preciseLocationBlocked: Flow<Boolean> = data.map { it[PRECISE_LOCATION_BLOCKED] ?: false }.distinctUntilChanged()

    suspend fun setPreciseLocationBlocked(blocked: Boolean) {
        store.edit { it[PRECISE_LOCATION_BLOCKED] = blocked }
    }

    /** Notifications were asked for once, after the first radio connected (§6.6); never asked unprompted again. */
    suspend fun notificationsAsked(): Boolean = data.map { it[NOTIFICATIONS_ASKED] ?: false }.first()

    suspend fun setNotificationsAsked() {
        store.edit { it[NOTIFICATIONS_ASKED] = true }
    }

    /** Android has stopped showing its notifications dialog: Turn on opens the app's notification settings. */
    val notificationsBlocked: Flow<Boolean> = data.map { it[NOTIFICATIONS_BLOCKED] ?: false }.distinctUntilChanged()

    suspend fun setNotificationsBlocked(blocked: Boolean) {
        store.edit { it[NOTIFICATIONS_BLOCKED] = blocked }
    }

    /** Everything, as on a first launch. */
    suspend fun clear() {
        store.edit { it.clear() }
    }

    /** The bound live radio; the same file, so [clear] forgets it too. */
    val radioRegistry: RadioRegistry = object : RadioRegistry {
        override val bound: Flow<BoundRadio?> = data.map(::boundRadio).distinctUntilChanged()

        override suspend fun bind(radio: BoundRadio) {
            store.edit { preferences ->
                RADIO_KEYS.forEach { preferences.remove(it) }
                preferences[RADIO_KIND] = radio.kind.name
                preferences[RADIO_LINK_ID] = radio.linkId
                radio.associationId?.let { preferences[RADIO_ASSOCIATION_ID] = it }
                radio.modelId?.let { preferences[RADIO_MODEL_ID] = it }
                radio.name?.let { preferences[RADIO_NAME] = it }
                preferences[RADIO_AUTO_CONNECT] = radio.autoConnect
                radio.pending?.let { preferences[RADIO_PENDING] = it.name }
            }
        }

        override suspend fun attached(linkId: String) {
            store.edit { preferences ->
                if (preferences[RADIO_LINK_ID] != linkId) return@edit
                preferences[RADIO_AUTO_CONNECT] = true
                preferences.remove(RADIO_PENDING)
            }
        }

        override suspend fun setAutoConnect(linkId: String, enabled: Boolean) {
            store.edit { if (it[RADIO_LINK_ID] == linkId) it[RADIO_AUTO_CONNECT] = enabled }
        }

        override suspend fun setName(linkId: String, name: String) {
            store.edit { if (it[RADIO_LINK_ID] == linkId) it[RADIO_NAME] = name }
        }

        override suspend fun clear(linkId: String) {
            store.edit { preferences ->
                if (preferences[RADIO_LINK_ID] == linkId) RADIO_KEYS.forEach { preferences.remove(it) }
            }
        }
    }

    /** Null when nothing is bound, or what is stored names no kind this build knows. */
    private fun boundRadio(preferences: Preferences): BoundRadio? {
        val linkId = preferences[RADIO_LINK_ID] ?: return null
        val kind = preferences[RADIO_KIND]?.let { name ->
            RadioKind.entries.firstOrNull { it.name == name && it != RadioKind.Staging }
        } ?: return null
        return BoundRadio(
            kind = kind,
            linkId = linkId,
            associationId = preferences[RADIO_ASSOCIATION_ID],
            modelId = preferences[RADIO_MODEL_ID],
            name = preferences[RADIO_NAME],
            autoConnect = preferences[RADIO_AUTO_CONNECT] ?: true,
            // One this build does not know reads as made for the attempt: released with it.
            pending = preferences[RADIO_PENDING]?.let { name ->
                PendingBinding.entries.firstOrNull { it.name == name } ?: PendingBinding.NewAssociation
            },
        )
    }

    private companion object {
        const val TAG = "umsh.preferences"
        val ONBOARDING = stringPreferencesKey("onboarding.step")
        val STAGING_ENABLED = booleanPreferencesKey("staging.enabled")
        val STAGING_WIFI_SCAN_ONLY = booleanPreferencesKey("staging.wifiScanOnly")
        val FALLBACK_SCHEME = booleanPreferencesKey("debug.fallbackScheme")
        val RECONNECT_STRATEGY = stringPreferencesKey("debug.reconnectStrategy")
        val NEARBY_BLOCKED = booleanPreferencesKey("permissions.nearby.blocked")
        val HIDE_LOCK_SCREEN = booleanPreferencesKey("notifications.hideLockScreen")
        val NOTIFICATIONS_ASKED = booleanPreferencesKey("notifications.asked")
        val NOTIFICATIONS_BLOCKED = booleanPreferencesKey("permissions.notifications.blocked")
        val LOCATION_BLOCKED = booleanPreferencesKey("permissions.location.blocked")
        val PRECISE_LOCATION_BLOCKED = booleanPreferencesKey("permissions.preciseLocation.blocked")
        val RADIO_KIND = stringPreferencesKey("radio.kind")
        val RADIO_LINK_ID = stringPreferencesKey("radio.linkId")
        val RADIO_ASSOCIATION_ID = stringPreferencesKey("radio.associationId")
        val RADIO_MODEL_ID = intPreferencesKey("radio.modelId")
        val RADIO_NAME = stringPreferencesKey("radio.name")
        val RADIO_AUTO_CONNECT = booleanPreferencesKey("radio.autoConnect")
        val RADIO_PENDING = stringPreferencesKey("radio.pending")
        val RADIO_KEYS = listOf(RADIO_KIND, RADIO_LINK_ID, RADIO_ASSOCIATION_ID, RADIO_MODEL_ID, RADIO_NAME, RADIO_AUTO_CONNECT, RADIO_PENDING)
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
        // The user's choice; the runtime clamps it to the grant before the core sees it.
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
        /** Share location: the identity carries this phone's position. */
        var shareLocation: Boolean
            get() = preferences[SHARE_LOCATION] ?: false
            set(value) { preferences[SHARE_LOCATION] = value }

        /** The precision the user chose; what the core gets may be coarser (`SharedPrecision`). */
        var locationPrecision: Int
            get() = preferences[LOCATION_PRECISION] ?: DEFAULT_LOCATION_PRECISION
            set(value) { preferences[LOCATION_PRECISION] = value }
        var testMessageAlerts: Boolean
            get() = preferences[TEST_MESSAGE_ALERTS] ?: false
            set(value) { preferences[TEST_MESSAGE_ALERTS] = value }
    }
}
