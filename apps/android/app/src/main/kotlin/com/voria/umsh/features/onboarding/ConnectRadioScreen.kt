package com.voria.umsh.features.onboarding

import android.content.ActivityNotFoundException
import androidx.activity.compose.LocalActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.IntentSenderRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.UmshApplication
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.BoardPhoto
import com.voria.umsh.designsystem.boardName
import com.voria.umsh.services.permissions.rememberBluetoothEnabler
import com.voria.umsh.services.permissions.rememberNearbyDevicesAsker

/**
 * Connect a radio (`onboarding.svg` boards 4–8), built against
 * [RadioScanSource]. Set up later finishes without a radio; a connected
 * radio ends onboarding. Back belongs to the host, which returns to
 * Welcome: a page with no back handler of its own gets the host's
 * predictive back preview (the system's, in an activity of its own).
 */
@Composable
fun ConnectRadioScreen(
    source: RadioScanSource,
    onSetUpLater: () -> Unit,
    onConnected: () -> Unit,
) {
    RadioScanPage(
        source = source,
        title = stringResource(R.string.connect_radio_title),
        onConnected = onConnected,
        modifier = Modifier.testTag(Tags.CONNECT_RADIO),
        bottomBar = {
            Box(Modifier.fillMaxWidth().padding(16.dp), contentAlignment = Alignment.Center) {
                TextButton(onClick = onSetUpLater, modifier = Modifier.testTag(Tags.SET_UP_LATER)) {
                    Text(stringResource(R.string.set_up_later))
                }
            }
        },
    )
}

/** The radio already set up, pinned at the top of Choose a radio (`radio-picker.svg` 1). */
data class PinnedRadio(
    /** Its address: the search's own row for it is left out. */
    val linkId: String?,
    val name: String,
    val modelId: Int?,
    /** Its state, as Radio Detail words it. */
    val state: String,
    /** It carries this phone now: the check. */
    val current: Boolean,
)

/**
 * The radio search's page: Connect a radio in onboarding, and Choose a
 * radio (`radio-picker.svg`), which adds [onBack] and the [pinned] radio
 * already set up. Looks while shown: the search starts with the page and
 * stops when it leaves, but not when the window is only being recreated
 * (a search kept in a ViewModel carries on, and with it a radio being
 * connected). Android's dialogs the search needs are raised from here.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RadioScanPage(
    source: RadioScanSource,
    title: String,
    onConnected: () -> Unit,
    modifier: Modifier = Modifier,
    onBack: (() -> Unit)? = null,
    pinned: PinnedRadio? = null,
    bottomBar: @Composable () -> Unit = {},
) {
    val state by source.state.collectAsStateWithLifecycle()
    val activity = LocalActivity.current
    DisposableEffect(source) {
        source.start()
        onDispose { if (activity?.isChangingConfigurations != true) source.stop() }
    }
    DisposableEffect(source, activity) {
        source.showing(activity)
        onDispose { source.showing(null) }
    }
    LaunchedEffect(state) { if (state == RadioScanState.Connected) onConnected() }
    // The process's: the page also runs outside the shell (onboarding, the debug preview).
    val preferences = (LocalContext.current.applicationContext as UmshApplication).coreHost.preferences
    val askNearby = rememberNearbyDevicesAsker(preferences)
    val turnOnBluetooth = rememberBluetoothEnabler(preferences)
    // Saveable: a result that comes back to a recreated window still reaches the search.
    val confirmRadio = rememberLauncherForActivityResult(ActivityResultContracts.StartIntentSenderForResult()) { result ->
        source.confirmed(result)
    }
    LaunchedEffect(source) {
        source.requests.collect { request ->
            when (request) {
                ScanRequest.AskNearbyDevices -> askNearby()
                ScanRequest.TurnOnBluetooth -> turnOnBluetooth()
                is ScanRequest.ConfirmRadio -> try {
                    confirmRadio.launch(IntentSenderRequest.Builder(request.sender).build())
                } catch (_: ActivityNotFoundException) {
                    source.confirmed(null)
                }
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    if (onBack != null) {
                        IconButton(onClick = onBack, modifier = Modifier.testTag(Tags.TOP_BAR_BACK)) {
                            Icon(painterResource(R.drawable.ic_arrow_back), contentDescription = stringResource(R.string.action_back))
                        }
                    }
                },
            )
        },
        bottomBar = bottomBar,
        modifier = modifier,
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when (val shown = state) {
                is RadioScanState.Looking -> RadioList(shown, pinned, onConnect = source::connect)
                RadioScanState.NearbyDenied -> Blocked(
                    stringResource(R.string.banner_nearby_denied_title),
                    stringResource(R.string.action_allow),
                    source::allow,
                )
                RadioScanState.BluetoothOff -> Blocked(
                    stringResource(R.string.banner_bluetooth_off_title),
                    stringResource(R.string.action_turn_on),
                    source::turnOn,
                )
                RadioScanState.BluetoothUnavailable -> Blocked(stringResource(R.string.bluetooth_unavailable), null) {}
                RadioScanState.Connected -> Unit
            }
        }
    }
}

@Composable
private fun RadioList(state: RadioScanState.Looking, held: PinnedRadio?, onConnect: (FoundRadio) -> Unit) {
    val connectingRadio = state.connecting
    // The radio being connected is held once the old one is let go: it
    // stays a row, with its progress, until it is up.
    val pinned = held?.takeIf { it.linkId == null || it.linkId != connectingRadio }
    LazyColumn(Modifier.fillMaxSize()) {
        item {
            Text(
                stringResource(R.string.available_radios),
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier
                    .padding(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 4.dp)
                    .semantics { heading() },
            )
        }
        if (pinned != null) {
            item(key = PINNED_KEY) {
                ListItem(
                    headlineContent = { Text(pinned.name) },
                    supportingContent = { Text(pinned.state) },
                    leadingContent = { BoardPhoto(pinned.modelId, Modifier.size(width = 56.dp, height = 48.dp)) },
                    trailingContent = if (pinned.current) {
                        { Icon(painterResource(R.drawable.ic_check), contentDescription = null, tint = MaterialTheme.colorScheme.primary) }
                    } else {
                        null
                    },
                    colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.background),
                    modifier = Modifier
                        .alpha(if (connectingRadio != null) DIMMED_ALPHA else 1f)
                        .semantics(mergeDescendants = true) { if (pinned.current) selected = true }
                        .testTag(Tags.CHOOSE_RADIO_CURRENT),
                )
            }
        }
        items(state.radios.filter { it.id != pinned?.linkId }, key = { it.id }) { radio ->
            val connecting = radio.id == connectingRadio
            val dimmed = connectingRadio != null && !connecting
            val connectingText = stringResource(R.string.connect_radio_row_connecting)
            val model = boardName(radio.modelId)
            ListItem(
                // Until the scan response names it, a radio goes by its
                // model, which is then not said twice.
                headlineContent = { Text(radio.name ?: model ?: stringResource(R.string.unknown_model)) },
                supportingContent = if (radio.name != null) {
                    { Text(model ?: stringResource(R.string.unknown_model)) }
                } else {
                    null
                },
                leadingContent = { BoardPhoto(radio.modelId, Modifier.size(width = 56.dp, height = 48.dp)) },
                trailingContent = if (connecting) {
                    { CircularProgressIndicator(Modifier.size(24.dp).testTag(Tags.CONNECT_RADIO_PROGRESS), strokeWidth = 3.dp) }
                } else {
                    null
                },
                colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.background),
                modifier = Modifier
                    .alpha(if (dimmed) DIMMED_ALPHA else 1f)
                    .clickable(enabled = connectingRadio == null) { onConnect(radio) }
                    .semantics { if (connecting) stateDescription = connectingText }
                    .testTag(Tags.CONNECT_RADIO_ROW),
            )
        }
        state.failure?.let { failure ->
            item {
                Text(
                    stringResource(
                        when (failure) {
                            ConnectFailure.PairingRemoved -> R.string.pairing_removed
                            ConnectFailure.BluetoothUnavailable -> R.string.bluetooth_unavailable
                            ConnectFailure.ConnectFailed -> R.string.connect_failed
                        },
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                    textAlign = TextAlign.Center,
                    // Appears in place of the row's progress: said when it does.
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 24.dp, vertical = 16.dp)
                        .semantics { liveRegion = LiveRegionMode.Polite }
                        .testTag(Tags.CONNECT_RADIO_FAILURE),
                )
            }
        }
        // Looking continues below the list, except while a row connects or after a failure.
        if (connectingRadio == null && state.failure == null) {
            item {
                Column(
                    Modifier.fillMaxWidth().padding(horizontal = 24.dp, vertical = 16.dp).testTag(Tags.CONNECT_RADIO_SEARCHING),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    Text(stringResource(R.string.looking_for_radios), style = MaterialTheme.typography.bodyLarge)
                    Text(
                        stringResource(R.string.open_pairing_window),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                    )
                }
            }
        }
    }
}

/** Nearby devices refused, Bluetooth off or unavailable: in place of the list. */
@Composable
private fun Blocked(title: String, action: String?, onAction: () -> Unit) {
    Column(
        Modifier.fillMaxSize().padding(24.dp).testTag(Tags.CONNECT_RADIO_BLOCKED),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp, Alignment.CenterVertically),
    ) {
        Text(
            title,
            style = MaterialTheme.typography.bodyLarge,
            textAlign = TextAlign.Center,
            // Replaces the list when Bluetooth or the permission goes: said when it does.
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
        )
        if (action != null) {
            FilledTonalButton(onClick = onAction, modifier = Modifier.testTag(Tags.CONNECT_RADIO_BLOCKED_ACTION)) {
                Text(action)
            }
        }
    }
}

private const val DIMMED_ALPHA = 0.38f

/** The pinned row's list key: no radio's address. */
private const val PINNED_KEY = "pinned"
