package com.voria.umsh.features.radio

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.LocalAppCoreHost
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.LocalShellViewModelStoreOwner
import com.voria.umsh.app.Tags
import com.voria.umsh.features.onboarding.PinnedRadio
import com.voria.umsh.features.onboarding.RadioScanPage
import com.voria.umsh.features.onboarding.rememberRadioSearch
import com.voria.umsh.services.radio.BoardCatalog
import kotlinx.coroutines.flow.catch

/**
 * Choose a radio (`radio-picker.svg` 1–2): the radio search's list, with
 * the radio held now pinned at the top. Choosing another radio releases
 * the current one first, as iOS does; the released radio stays associated,
 * so it is still listed here out of its pairing window (§2.2), and
 * choosing it again needs no confirmation. A chosen radio that comes up
 * closes the page ([onChosen]).
 *
 * Opened by Radio Detail's Choose another radio, and with no radio set up
 * by the radio control, the banner's Choose radio, the composer's Connect
 * radio and Settings' Companion radio (D20).
 */
@Composable
fun RadioPickerScreen(onBack: () -> Unit, onChosen: () -> Unit) {
    val host = LocalAppCoreHost.current
    val runtime = LocalAppRuntime.current
    // The shell's store: the search outlives a window recreated mid-connect,
    // and stops when the page leaves.
    val search = rememberRadioSearch(KEY, owner = LocalShellViewModelStoreOwner.current, offersAssociated = true)
    val radio by runtime.radio.collectAsStateWithLifecycle()
    val bound by remember(host) { host.preferences.radioRegistry.bound.catch { emit(null) } }
        .collectAsStateWithLifecycle(initialValue = null)
    val context = LocalContext.current
    val catalog = remember(context) { BoardCatalog.bundled(context) }

    val held = radio
    val pinned = held?.let {
        val registered = bound?.takeIf { it.linkId == held.linkId }
        val modelId = registered?.modelId
        PinnedRadio(
            linkId = held.linkId,
            name = held.name ?: registered?.name ?: catalog.board(modelId)?.name ?: stringResource(R.string.unknown_model),
            modelId = modelId,
            state = if (held.carriesThisPhone) {
                stringResource(R.string.radio_row_connected)
            } else {
                stringResource(RadioDetailModel.status(held.phase).label)
            },
            current = held.carriesThisPhone,
        )
    }
    RadioScanPage(
        source = search,
        title = stringResource(R.string.choose_radio_title),
        onConnected = onChosen,
        onBack = onBack,
        pinned = pinned,
        modifier = Modifier.testTag(Tags.CHOOSE_RADIO),
    )
}

private const val KEY = "radio-picker"
