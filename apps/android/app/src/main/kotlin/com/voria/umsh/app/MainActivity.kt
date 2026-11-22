package com.voria.umsh.app

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.voria.umsh.BuildConfig
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private val host: AppCoreHost get() = (application as UmshApplication).coreHost

    override fun onCreate(savedInstanceState: Bundle?) {
        installSplashScreen().setKeepOnScreenCondition { host.state.value is HostState.Starting }
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        // Debug builds: `--ez umsh.staging true|false` picks the core, for
        // tests and screenshot runs. Only on a fresh launch: not a restore,
        // and not a relaunch from Recents, which replays the first intent.
        val fresh = savedInstanceState == null &&
            intent.flags and Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY == 0
        val staging = if (BuildConfig.DEBUG && fresh && intent.hasExtra(EXTRA_STAGING)) {
            intent.getBooleanExtra(EXTRA_STAGING, false)
        } else {
            null
        }
        host.ensureRuntime(staging)
        lifecycleScope.launch {
            // A task resumed after an erase goes to the first-launch path,
            // never the old shell.
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                host.state.collect { if (it is HostState.NeedsFirstLaunch) host.ensureRuntime() }
            }
        }
        setContent { AppRoot(host) }
    }

    companion object {
        const val EXTRA_STAGING = "umsh.staging"
    }
}
