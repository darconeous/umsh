package com.voria.umsh.app

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.res.Configuration
import android.os.LocaleList
import android.os.StrictMode
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.voria.umsh.BuildConfig
import com.voria.umsh.core.MobileLogLevel
import com.voria.umsh.core.setLogger
import com.voria.umsh.services.background.PresenceObservations
import com.voria.umsh.services.background.RadioPresence
import com.voria.umsh.services.background.RadioServiceController
import com.voria.umsh.services.background.ReconnectStrategy
import com.voria.umsh.services.background.UserStop
import com.voria.umsh.services.location.PhoneLocation
import com.voria.umsh.services.location.PhoneLocationSource
import com.voria.umsh.services.mobilecore.AppLog
import com.voria.umsh.services.mobilecore.CoreLogger
import com.voria.umsh.services.notifications.MessageNotifier
import com.voria.umsh.services.notifications.NotificationChannels
import com.voria.umsh.services.preferences.AppPreferences
import com.voria.umsh.features.onboarding.RadioScanSource
import com.voria.umsh.services.radio.BleRadioScanSource
import com.voria.umsh.services.radio.BleScanner
import com.voria.umsh.services.radio.BluetoothAvailability
import com.voria.umsh.services.radio.BluetoothStatus
import com.voria.umsh.services.radio.CompanionAssociations
import com.voria.umsh.services.radio.HostRadioConnector
import com.voria.umsh.services.radio.RadioLinkFactory
import com.voria.umsh.services.radio.RadioLinks
import java.time.Clock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.plus

/**
 * The process, and the one [AppCoreHost] in it.
 *
 * Opens and starts nothing: the host is constructed here and brought up
 * by `MainActivity` (or, never minting, by the radio's service), so a
 * process started for another reason (Manage space, a test) never touches
 * the store or the identity unasked. The core's logger, the notification
 * channels, the notifier and the radio service's controller are what is
 * set up here.
 */
open class UmshApplication : Application() {
    /** Replaced only by instrumented tests, from their own thread. */
    @Volatile
    lateinit var coreHost: AppCoreHost
        private set

    /** Starts the radio's foreground service and says what it shows; follows [coreHost]. */
    @Volatile
    lateinit var radioService: RadioServiceController
        private set

    private var radioServiceScope: CoroutineScope? = null

    /** Posts what the core asks to be told; handed every host's runtimes. One per process. */
    lateinit var notifier: MessageNotifier
        private set

    /** Work that outlives what asked for it, such as a notification action's. */
    val backgroundScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /** Where everything is kept; tests point it elsewhere. */
    protected open fun appPaths(): AppPaths = AppPaths.of(this)

    /** Whether Bluetooth is on and Nearby devices granted; one per process. */
    lateinit var bluetooth: BluetoothAvailability
        private set

    /** The radios associated through CompanionDeviceManager; one per process. */
    lateinit var associations: CompanionAssociations
        private set

    /**
     * The Developer switch's choice of what follows the reconnect window
     * (D7), followed from the current host's preferences; Presence until
     * read, and always in release builds.
     */
    val preferredStrategy = MutableStateFlow(ReconnectStrategy.Presence)

    /**
     * Where Android observes the bound radio's presence. Tests observe
     * nothing: their hosts' registries are their own, and following one
     * would stop what the installed app asked Android to watch.
     */
    protected open fun presenceObservations(): PresenceObservations = associations

    /** The links a bound radio is reached over; tests add scripted ones. */
    protected open fun radioLinks(): RadioLinkFactory = RadioLinks(this, bluetooth, associations, preferredStrategy)

    /**
     * The search Connect a radio and Choose a radio list radios from: the
     * Bluetooth scan, whose rows connect through the host. Choose a radio
     * ([offersAssociated]) also lists the radios already associated, such
     * as one released by choosing another (§2.2). Tests swap in a stand-in.
     */
    open fun radioSearch(offersAssociated: Boolean): RadioScanSource =
        BleRadioScanSource(
            bluetooth.status,
            BleScanner(this),
            HostRadioConnector(coreHost, associations),
            associated = if (offersAssociated) {
                { associations.inventory().keys }
            } else {
                { emptySet() }
            },
        )

    /**
     * Nearby devices was just granted from inside the app: no ON_START
     * follows a permission dialog, so the grant is read now, and the radio's
     * service is started if it was held back for want of it.
     */
    fun nearbyDevicesAnswered() {
        bluetooth.refresh()
        radioService.nearbyDevicesAnswered()
    }

    /** Whether the user stopped the app and has not opened it since; one per process. */
    lateinit var userStop: UserStop
        private set

    /** This phone's location readings and grant: one per process, read by every runtime. */
    lateinit var phoneLocation: PhoneLocation
        private set

    /** The source the host's runtimes read; tests swap in a stand-in. */
    protected open fun phoneLocationSource(): PhoneLocationSource = phoneLocation

    private val foregroundSignals =
        MutableSharedFlow<Unit>(extraBufferCapacity = 1, onBufferOverflow = BufferOverflow.DROP_OLDEST)

    override fun onCreate() {
        super.onCreate()
        if (BuildConfig.DEBUG) enableStrictMode()
        AppLog.sink = AppLog.Sink { level, tag, message ->
            val priority = when (level) {
                AppLog.Level.Error -> Log.ERROR
                AppLog.Level.Warn -> Log.WARN
                AppLog.Level.Info -> Log.INFO
                AppLog.Level.Debug -> Log.DEBUG
            }
            Log.println(priority, tag, message)
        }
        setLogger(
            CoreLogger(includePrivate = BuildConfig.DEBUG),
            if (BuildConfig.DEBUG) MobileLogLevel.DEBUG else MobileLogLevel.INFO,
        )

        // Read before anything can start the radio headless; off the main thread (disk and binder).
        userStop = UserStop(
            UserStop.preferences(this),
            { UserStop.exits(this) },
            backgroundScope + Dispatchers.IO,
        )
        bluetooth = BluetoothAvailability(this)
        associations = CompanionAssociations(this)
        phoneLocation = PhoneLocation(this)
        channelLocales = resources.configuration.locales
        NotificationChannels.ensure(this)
        notifier = MessageNotifier(
            context = this,
            hideOnLockScreen = { coreHost.preferences.hideLockScreenContents.first() },
            openConversation = { address -> MainActivity.conversationIntent(this, address) },
            openPeer = { address -> MainActivity.peerIntent(this, address) },
        )
        notifier.watchProcess()
        coreHost = makeHost(appPaths())
        followHost()

        ProcessLifecycleOwner.get().lifecycle.addObserver(
            object : DefaultLifecycleObserver {
                override fun onStart(owner: LifecycleOwner) {
                    // A grant changed in Settings is read before anything acts on it.
                    bluetooth.refresh()
                    // And the location grant, before the next reading is taken under it (§3.8).
                    phoneLocationSource().refresh()
                    phoneLocation.setInUse(true)
                    foregroundSignals.tryEmit(Unit)
                }

                override fun onStop(owner: LifecycleOwner) {
                    // No background location (D9): readings stop; the core keeps the last.
                    phoneLocation.setInUse(false)
                    // The last keystrokes survive backgrounding and process death.
                    coreHost.flushDrafts()
                }
            },
        )
        ContextCompat.registerReceiver(
            this,
            object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) {
                    coreHost.timeChanged()
                    // The channels' names in Android's settings follow the language.
                    if (intent.action == Intent.ACTION_LOCALE_CHANGED) NotificationChannels.ensure(context)
                }
            },
            IntentFilter().apply {
                addAction(Intent.ACTION_TIME_CHANGED)
                addAction(Intent.ACTION_TIMEZONE_CHANGED)
                addAction(Intent.ACTION_LOCALE_CHANGED)
                addAction(Intent.ACTION_DATE_CHANGED)
            },
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    /** A per-app language change reaches the channels' names here; a system one, by broadcast too. */
    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        if (newConfig.locales != channelLocales) {
            channelLocales = newConfig.locales
            NotificationChannels.ensure(this)
        }
    }

    /** The languages the channels were last named in. */
    private var channelLocales: LocaleList? = null

    /** Tests: a new host over [paths], in place of one already shut down. */
    protected fun replaceHost(paths: AppPaths) {
        coreHost = makeHost(paths)
        followHost()
    }

    private fun followHost() {
        radioServiceScope?.cancel()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
        radioServiceScope = scope
        val preferences = coreHost.preferences
        scope.launch { preferences.reconnectStrategy.collect { preferredStrategy.value = it } }
        radioService = RadioServiceController(
            this,
            coreHost,
            foregroundSignals,
            scope,
            preferredStrategy = preferredStrategy,
            presenceAvailable = associations.available,
            bluetoothOn = {
                bluetooth.refresh()
                bluetooth.status.value.adapter == BluetoothStatus.Adapter.On
            },
            awaitBluetoothOn = { bluetooth.status.first { it.adapter == BluetoothStatus.Adapter.On } },
            stoppedByUser = userStop::stopped,
        )
        // Off the main thread: CompanionDeviceManager's calls are binder calls.
        RadioPresence(presenceObservations(), preferences.radioRegistry.bound, preferredStrategy, scope + Dispatchers.Default)
    }

    private fun makeHost(paths: AppPaths) = AppCoreHost(
        paths = paths,
        vaults = KeystoreVaults(paths),
        preferences = AppPreferences(paths.preferences, CoroutineScope(Dispatchers.IO + SupervisorJob())),
        platformModel = {
            if (resources.configuration.smallestScreenWidthDp >= TABLET_WIDTH_DP) TABLET_MODEL else PHONE_MODEL
        },
        clock = Clock.systemDefaultZone(),
        foregroundSignals = foregroundSignals,
        stagingAvailable = BuildConfig.DEBUG,
        radioLinks = radioLinks(),
        scope = CoroutineScope(SupervisorJob() + Dispatchers.Default),
        notifications = notifier,
        bluetooth = bluetooth.status,
        bindings = associations,
        location = phoneLocationSource(),
    )

    /** Logs disk and network access on the main thread, and leaks. */
    private fun enableStrictMode() {
        StrictMode.setThreadPolicy(
            StrictMode.ThreadPolicy.Builder().detectAll().penaltyLog().build(),
        )
        StrictMode.setVmPolicy(
            StrictMode.VmPolicy.Builder().detectAll().penaltyLog().build(),
        )
    }

    private companion object {
        /** `docs/hardware/platforms.json`: Android phone and tablet. */
        const val PHONE_MODEL: UShort = 65026u
        const val TABLET_MODEL: UShort = 65027u
        const val TABLET_WIDTH_DP = 600
    }
}
