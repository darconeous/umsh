package com.voria.umsh.features.onboarding

import androidx.compose.foundation.background
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
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.Tags

/**
 * Connect a radio (`onboarding.svg` boards 4–8), built against
 * [RadioScanSource]. Set up later finishes without a radio; a connected
 * radio ends onboarding. Back belongs to the host, which returns to
 * Welcome: a page with no back handler of its own gets the host's
 * predictive back preview (the system's, in an activity of its own).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConnectRadioScreen(
    source: RadioScanSource,
    onSetUpLater: () -> Unit,
    onConnected: () -> Unit,
) {
    val state by source.state.collectAsStateWithLifecycle()
    DisposableEffect(source) {
        source.start()
        onDispose { source.stop() }
    }
    LaunchedEffect(state) { if (state == RadioScanState.Connected) onConnected() }

    Scaffold(
        topBar = { TopAppBar(title = { Text(stringResource(R.string.connect_radio_title)) }) },
        bottomBar = {
            Box(Modifier.fillMaxWidth().padding(16.dp), contentAlignment = Alignment.Center) {
                TextButton(onClick = onSetUpLater, modifier = Modifier.testTag(Tags.SET_UP_LATER)) {
                    Text(stringResource(R.string.set_up_later))
                }
            }
        },
        modifier = Modifier.testTag(Tags.CONNECT_RADIO),
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when (val shown = state) {
                is RadioScanState.Looking -> RadioList(shown, onConnect = source::connect)
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
private fun RadioList(state: RadioScanState.Looking, onConnect: (FoundRadio) -> Unit) {
    val connectingRadio = state.connecting
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
        items(state.radios, key = { it.id }) { radio ->
            val connecting = radio.id == connectingRadio
            val dimmed = connectingRadio != null && !connecting
            val connectingText = stringResource(R.string.connect_radio_row_connecting)
            ListItem(
                headlineContent = { Text(radio.name) },
                supportingContent = { Text(radio.model ?: stringResource(R.string.unknown_model)) },
                leadingContent = { RadioTile() },
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

/** The board's photo goes here once the shared board list ships (Phase 2); until then the radio glyph. */
@Composable
private fun RadioTile() {
    Box(
        Modifier
            .size(48.dp)
            .background(MaterialTheme.colorScheme.surfaceContainerHighest, MaterialTheme.shapes.small),
        contentAlignment = Alignment.Center,
    ) {
        Icon(painterResource(R.drawable.ic_sensors), contentDescription = null, tint = MaterialTheme.colorScheme.onSurfaceVariant)
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
