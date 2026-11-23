package com.voria.umsh.features.onboarding

import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelStoreOwner
import androidx.lifecycle.viewmodel.compose.LocalViewModelStoreOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import com.voria.umsh.app.UmshApplication

/**
 * Holds a radio search across a window's recreation, so a radio being
 * confirmed, paired and attached is not called off by a rotation, and
 * Android's confirmation answers the search that raised it. The page
 * starts and stops the search; this only stops it for good.
 */
class RadioSearchViewModel(val source: RadioScanSource) : ViewModel() {
    override fun onCleared() {
        source.stop()
    }
}

/**
 * The app's radio search ([UmshApplication.radioSearch]), kept in [owner]
 * under [key]; [offersAssociated] for Choose a radio.
 */
@Composable
fun rememberRadioSearch(
    key: String,
    owner: ViewModelStoreOwner = checkNotNull(LocalViewModelStoreOwner.current) { "no ViewModelStoreOwner" },
    offersAssociated: Boolean = false,
): RadioScanSource {
    val app = LocalContext.current.applicationContext as UmshApplication
    return viewModel(owner, key) { RadioSearchViewModel(app.radioSearch(offersAssociated)) }.source
}
