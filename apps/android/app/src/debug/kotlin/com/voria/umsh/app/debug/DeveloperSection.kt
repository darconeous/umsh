package com.voria.umsh.app.debug

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.content.Intent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringArrayResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.AppCoreHost
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.CoreKind
import com.voria.umsh.app.Tags
import com.voria.umsh.services.background.ReconnectStrategy
import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.RadioControlState
import com.voria.umsh.services.radio.RadioKind
import com.voria.umsh.services.radio.TcpEndpoint
import kotlinx.coroutines.launch

/** As another client spells reactions on the wire. */
private val REACTION_TOKENS = listOf("<3", "+1", "-1", "ha", "!", "?")
private const val STAGED_DELAY_MS = 5_000L

/**
 * Settings › Developer (debug builds): staging mode and the staged mesh's
 * levers, so the change pump drives the screens live.
 */
@Composable
fun DeveloperSection(host: AppCoreHost, runtime: AppRuntime) {
    val scope = rememberCoroutineScope()
    val staging = runtime.kind == CoreKind.Staging
    val wifiScanOnly by host.preferences.stagingWifiScanOnly.collectAsStateWithLifecycle(initialValue = false)
    val fallback by host.preferences.fallbackScheme.collectAsStateWithLifecycle(initialValue = false)
    val air by host.stagingRadio.collectAsStateWithLifecycle()
    val strategy by host.preferences.reconnectStrategy.collectAsStateWithLifecycle(initialValue = ReconnectStrategy.Presence)
    val radio by runtime.radio.collectAsStateWithLifecycle()
    var resetFailed by remember { mutableStateOf(false) }
    val lines = stringArrayResource(R.array.developer_peer_lines)
    val reply = stringResource(R.string.developer_peer_reply)

    Column {
        Text(
            stringResource(R.string.developer_title),
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier
                .padding(start = 16.dp, end = 16.dp, top = 24.dp, bottom = 4.dp)
                .semantics { heading() },
        )
        // The running kind, not the stored choice: a launch extra can override it.
        SwitchRow(stringResource(R.string.developer_staging_mode), stringResource(R.string.developer_staging_detail), staging, Tags.DEV_STAGING) {
            host.setStaging(it)
        }
        SwitchRow(stringResource(R.string.developer_wifi_scan_only), stringResource(R.string.developer_wifi_scan_only_detail), wifiScanOnly) {
            scope.launch { host.preferences.setStagingWifiScanOnly(it) }
        }
        SwitchRow(stringResource(R.string.developer_fallback_colors), null, fallback, Tags.DEV_FALLBACK_COLORS) {
            scope.launch { host.preferences.setFallbackScheme(it) }
        }
        air?.let { connection ->
            val linkUp = RadioControlState.from(radio).link in setOf(
                RadioControlState.Link.Connected,
                RadioControlState.Link.Connecting,
                RadioControlState.Link.Reconnecting,
            )
            SwitchRow(stringResource(R.string.developer_link_up), null, linkUp, Tags.DEV_LINK_UP) { connection.setLinkUp(it) }
            var failing by remember(connection) { mutableStateOf(connection.transmissionsFailing) }
            SwitchRow(stringResource(R.string.developer_tx_failing), null, failing, Tags.DEV_TX_FAILING) {
                connection.setTransmissionsFailing(it)
                failing = connection.transmissionsFailing
            }
            ActionRow(stringResource(R.string.developer_peer_says)) {
                connection.later(STAGED_DELAY_MS) { peerSays(lines.random(), onChannel = false) }
            }
            ActionRow(stringResource(R.string.developer_peer_says_channel)) {
                connection.later(STAGED_DELAY_MS) { peerSays(lines.random(), onChannel = true) }
            }
            ActionRow(stringResource(R.string.developer_peer_loses_one)) {
                val (first, lost, last) = lines.toList().shuffled()
                connection.later(0) { peerSaysLosingOne(first, lost, last) }
            }
            ActionRow(stringResource(R.string.developer_peer_reacts)) {
                connection.later(STAGED_DELAY_MS) { peerReacts(REACTION_TOKENS.random()) }
            }
            ActionRow(stringResource(R.string.developer_peer_replies)) {
                connection.later(STAGED_DELAY_MS) { peerReplies(reply) }
            }
        }
        BridgedRadioRows(host)
        BondedRadioRows(host)
        // D7: what follows the reconnect window; Presence unless switched.
        SwitchRow(
            stringResource(R.string.developer_waiting_strategy),
            null,
            strategy == ReconnectStrategy.Waiting,
            Tags.DEV_WAITING_STRATEGY,
        ) { waiting ->
            scope.launch { host.preferences.setReconnectStrategy(if (waiting) ReconnectStrategy.Waiting else ReconnectStrategy.Presence) }
        }
        AddPeerRows(runtime)
        val context = LocalContext.current
        ActionRow(stringResource(R.string.developer_connect_radio_preview), Tags.DEV_CONNECT_RADIO_PREVIEW) {
            context.startActivity(Intent(context, ConnectRadioPreviewActivity::class.java))
        }
        ActionRow(stringResource(R.string.developer_connect_radio_live), Tags.DEV_CONNECT_RADIO_LIVE) {
            context.startActivity(
                Intent(context, ConnectRadioPreviewActivity::class.java)
                    .putExtra(ConnectRadioPreviewActivity.EXTRA_SCENARIO, ConnectRadioPreviewActivity.SCENARIO_LIVE),
            )
        }
        ActionRow(stringResource(R.string.developer_reset_staged)) {
            scope.launch { resetFailed = !host.resetStagedData().await() }
        }
        if (resetFailed) {
            Text(
                stringResource(R.string.developer_reset_failed),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(horizontal = 16.dp),
            )
        }
    }
}

/**
 * The bridged radio: a `umsh-bridge` host interface over TCP (`make
 * android-bridge`), bound as the live core's radio. Connect binds and
 * connects; Disconnect and Forget are the radio's own commands.
 */
@Composable
private fun BridgedRadioRows(host: AppCoreHost) {
    val bound by host.preferences.radioRegistry.bound.collectAsStateWithLifecycle(initialValue = null)
    val boundEndpoint = bound?.takeIf { it.kind == RadioKind.Tcp }?.linkId
    var text by remember(boundEndpoint) { mutableStateOf(boundEndpoint ?: TcpEndpoint.DEFAULT) }
    val endpoint = TcpEndpoint.parse(text)
    OutlinedTextField(
        value = text,
        onValueChange = { text = it },
        label = { Text(stringResource(R.string.developer_bridged_radio)) },
        supportingText = {
            Text(stringResource(if (endpoint == null) R.string.developer_bridged_radio_invalid else R.string.developer_bridged_radio_detail))
        },
        isError = endpoint == null,
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Done),
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .testTag(Tags.DEV_BRIDGED_RADIO),
    )
    Row {
        ActionRow(stringResource(R.string.developer_bridged_connect), Tags.DEV_BRIDGED_CONNECT, enabled = endpoint != null) {
            endpoint?.let { host.connectRadio(BoundRadio(RadioKind.Tcp, it.text)) }
        }
        ActionRow(stringResource(R.string.developer_bridged_disconnect), Tags.DEV_BRIDGED_DISCONNECT, enabled = boundEndpoint != null) {
            host.disconnectRadio()
        }
        ActionRow(stringResource(R.string.developer_bridged_forget), Tags.DEV_BRIDGED_FORGET, enabled = boundEndpoint != null) {
            host.forgetRadio()
        }
    }
}

/**
 * Radios already bonded to this phone (paired in Settings › Bluetooth),
 * each bound and connected over Bluetooth on a tap: the radio link with no
 * search and no companion association. Listed only with Nearby devices
 * granted, which reading the bonds needs.
 */
@SuppressLint("MissingPermission")
@Composable
private fun BondedRadioRows(host: AppCoreHost) {
    val context = LocalContext.current
    val status by host.bluetooth.collectAsStateWithLifecycle()
    val bonded = remember(status) {
        if (!status.usable) {
            emptyList()
        } else {
            context.getSystemService(BluetoothManager::class.java)?.adapter?.bondedDevices.orEmpty()
                .filter { it.type == BluetoothDevice.DEVICE_TYPE_LE || it.type == BluetoothDevice.DEVICE_TYPE_DUAL }
                .map { it.address to (it.name ?: it.address) }
        }
    }
    Text(
        stringResource(R.string.developer_bonded_radios),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
    )
    for ((address, name) in bonded) {
        ActionRow(stringResource(R.string.developer_bonded_connect, name, address), Tags.DEV_BONDED_CONNECT) {
            host.connectRadio(BoundRadio(RadioKind.Ble, address, name = name))
        }
    }
}

/**
 * Add a peer by its key or `umsh:` link and open its conversation: a peer
 * the phone has never heard advertise (a `umshctl` node) otherwise lists
 * no conversation for what it sends (`air_tests`' unsolicited message).
 */
@Composable
private fun AddPeerRows(runtime: AppRuntime) {
    val scope = rememberCoroutineScope()
    var text by remember { mutableStateOf("") }
    var result by remember { mutableStateOf<Boolean?>(null) }
    OutlinedTextField(
        value = text,
        onValueChange = {
            text = it
            result = null
        },
        label = { Text(stringResource(R.string.developer_add_peer)) },
        supportingText = {
            Text(
                stringResource(
                    when (result) {
                        true -> R.string.developer_add_peer_added
                        false -> R.string.developer_add_peer_failed
                        null -> R.string.developer_add_peer_detail
                    },
                ),
            )
        },
        isError = result == false,
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii, imeAction = ImeAction.Done),
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .testTag(Tags.DEV_ADD_PEER),
    )
    ActionRow(stringResource(R.string.developer_add_peer_action), Tags.DEV_ADD_PEER_ACTION, enabled = text.isNotBlank()) {
        val input = text.trim()
        scope.launch {
            result = runCatching {
                runtime.core.savePeer(input, null, true)
                runtime.reload(full = true).await()
            }.isSuccess
        }
    }
}

@Composable
private fun SwitchRow(title: String, detail: String?, checked: Boolean, tag: String? = null, onChange: (Boolean) -> Unit) {
    // The whole row toggles, and TalkBack hears one switch named by the row.
    ListItem(
        headlineContent = { Text(title) },
        supportingContent = detail?.let { { Text(it) } },
        trailingContent = { Switch(checked = checked, onCheckedChange = null) },
        modifier = Modifier
            .toggleable(value = checked, role = Role.Switch, onValueChange = onChange)
            .then(tag?.let { Modifier.testTag(it) } ?: Modifier),
    )
}

@Composable
private fun ActionRow(title: String, tag: String? = null, enabled: Boolean = true, onClick: () -> Unit) {
    TextButton(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.padding(horizontal = 4.dp).then(tag?.let { Modifier.testTag(it) } ?: Modifier),
    ) { Text(title) }
}

/**
 * Storage unavailable over the staging store: Reset staged data, the
 * Developer section's, which the shell no longer reaches. It turns staging
 * off and throws the staged set away; the live identity is never touched
 * (D16).
 */
@Composable
fun StagingStoreActions(host: AppCoreHost) {
    val scope = rememberCoroutineScope()
    var resetFailed by remember { mutableStateOf(false) }
    OutlinedButton(
        onClick = { scope.launch { resetFailed = !host.resetStagedData().await() } },
        modifier = Modifier.padding(top = 8.dp).testTag(Tags.DEV_RESET_STAGED),
    ) {
        Text(stringResource(R.string.developer_reset_staged))
    }
    if (resetFailed) {
        Text(
            stringResource(R.string.developer_reset_failed),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
        )
    }
}
