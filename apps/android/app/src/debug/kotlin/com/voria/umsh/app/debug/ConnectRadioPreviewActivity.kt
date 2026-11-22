package com.voria.umsh.app.debug

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.app.UmshApplication
import com.voria.umsh.designsystem.UmshTheme
import com.voria.umsh.features.onboarding.ConnectRadioScreen

/**
 * Debug builds: Connect a radio over the fake search, from the Developer
 * section or `adb shell am start -n …/.app.debug.ConnectRadioPreviewActivity
 * --es scenario found|looking|connecting|failed|denied|off|unavailable`.
 * Changes nothing: Set up later, Back and a connection all just close it;
 * Back is the activity's own, with the system's predictive preview.
 */
class ConnectRadioPreviewActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        val preferences = (application as UmshApplication).coreHost.preferences
        val scenario = intent.getStringExtra(EXTRA_SCENARIO)
        setContent {
            val fallback by preferences.fallbackScheme.collectAsStateWithLifecycle(initialValue = false)
            val source = remember { FakeRadioScanSource.scenario(scenario) }
            UmshTheme(fallbackScheme = fallback) {
                Surface(Modifier.fillMaxSize()) {
                    ConnectRadioScreen(source, onSetUpLater = ::finish, onConnected = ::finish)
                }
            }
        }
    }

    companion object {
        const val EXTRA_SCENARIO = "scenario"
    }
}
