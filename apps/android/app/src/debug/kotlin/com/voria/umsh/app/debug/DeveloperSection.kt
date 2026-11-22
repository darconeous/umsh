package com.voria.umsh.app.debug

import android.content.Intent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.AppCoreHost
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.CoreKind
import com.voria.umsh.app.Tags
import com.voria.umsh.services.radio.RadioControlState
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
        val context = LocalContext.current
        ActionRow(stringResource(R.string.developer_connect_radio_preview), Tags.DEV_CONNECT_RADIO_PREVIEW) {
            context.startActivity(Intent(context, ConnectRadioPreviewActivity::class.java))
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
private fun ActionRow(title: String, tag: String? = null, onClick: () -> Unit) {
    TextButton(
        onClick = onClick,
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
