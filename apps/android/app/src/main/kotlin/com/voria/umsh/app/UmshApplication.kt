package com.voria.umsh.app

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.StrictMode
import android.util.Log
import androidx.core.content.ContextCompat
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.voria.umsh.BuildConfig
import com.voria.umsh.core.MobileLogLevel
import com.voria.umsh.core.setLogger
import com.voria.umsh.services.mobilecore.AppLog
import com.voria.umsh.services.mobilecore.CoreLogger
import com.voria.umsh.services.preferences.AppPreferences
import java.time.Clock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow

/**
 * The process, and the one [AppCoreHost] in it.
 *
 * Opens and starts nothing: the host is constructed here and brought up
 * by `MainActivity`, so a process started for another reason (Manage space,
 * a test) never touches the store or the identity unasked. The core's
 * logger is the one thing set here.
 */
open class UmshApplication : Application() {
    /** Replaced only by instrumented tests, from their own thread. */
    @Volatile
    lateinit var coreHost: AppCoreHost
        private set

    /** Where everything is kept; tests point it elsewhere. */
    protected open fun appPaths(): AppPaths = AppPaths.of(this)

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

        coreHost = makeHost(appPaths())

        ProcessLifecycleOwner.get().lifecycle.addObserver(
            object : DefaultLifecycleObserver {
                override fun onStart(owner: LifecycleOwner) {
                    foregroundSignals.tryEmit(Unit)
                }

                override fun onStop(owner: LifecycleOwner) {
                    // The last keystrokes survive backgrounding and process death.
                    coreHost.flushDrafts()
                }
            },
        )
        ContextCompat.registerReceiver(
            this,
            object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) = coreHost.timeChanged()
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

    /** Tests: a new host over [paths], in place of one already shut down. */
    protected fun replaceHost(paths: AppPaths) {
        coreHost = makeHost(paths)
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
        scope = CoroutineScope(SupervisorJob() + Dispatchers.Default),
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
