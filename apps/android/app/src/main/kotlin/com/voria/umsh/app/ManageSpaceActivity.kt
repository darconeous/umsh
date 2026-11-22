package com.voria.umsh.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.voria.umsh.BuildConfig
import com.voria.umsh.designsystem.NoticeHost
import com.voria.umsh.designsystem.UmshTheme
import com.voria.umsh.features.settings.ManageSpaceScreen
import com.voria.umsh.features.settings.ManageSpaceViewModel
import kotlinx.coroutines.flow.flowOf

/**
 * Manage space (`manage-space.svg`), Android's App info › Storage button in
 * place of Clear storage (`android:manageSpaceActivity`). Starts nothing:
 * it reads what is stored, and both its actions go through the host's one
 * erase, which stops a running core first. Done, it closes back to the
 * system page.
 */
class ManageSpaceActivity : ComponentActivity() {
    private val host: AppCoreHost get() = (application as UmshApplication).coreHost

    private val viewModel: ManageSpaceViewModel by viewModels {
        viewModelFactory { initializer { ManageSpaceViewModel(host) } }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        setContent {
            val fallback by remember {
                if (BuildConfig.DEBUG) host.preferences.fallbackScheme else flowOf(false)
            }.collectAsStateWithLifecycle(initialValue = false)
            val done by viewModel.done.collectAsStateWithLifecycle()
            LaunchedEffect(done) { if (done) finish() }
            UmshTheme(fallbackScheme = fallback) {
                Surface(Modifier.fillMaxSize()) {
                    NoticeHost { ManageSpaceScreen(viewModel, onBack = ::finish) }
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        viewModel.refresh()
    }
}
