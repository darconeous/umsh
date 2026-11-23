package com.voria.umsh.features.radio

import android.icu.text.MeasureFormat
import android.icu.text.NumberFormat
import android.icu.util.Measure
import android.icu.util.MeasureUnit
import androidx.activity.compose.LocalActivity
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.voria.umsh.R
import com.voria.umsh.app.LocalAppCoreHost
import com.voria.umsh.app.LocalShellViewModelStoreOwner
import com.voria.umsh.app.Tags
import com.voria.umsh.app.runtimeViewModel
import com.voria.umsh.core.SavedSnapshotRecord
import com.voria.umsh.designsystem.BoardPhoto
import com.voria.umsh.designsystem.ConfirmDialog
import com.voria.umsh.designsystem.DetailPane
import com.voria.umsh.designsystem.FailureDialog
import com.voria.umsh.designsystem.PeerAvatar
import com.voria.umsh.designsystem.RadioControlMetrics
import com.voria.umsh.designsystem.SectionHeader
import com.voria.umsh.designsystem.UmshColors
import com.voria.umsh.designsystem.UmshScaffold
import com.voria.umsh.designsystem.UmshTopAppBar
import com.voria.umsh.designsystem.ageText
import com.voria.umsh.designsystem.batteryGlyph
import com.voria.umsh.designsystem.identifierAnnotated
import com.voria.umsh.designsystem.rememberDisplayNames
import com.voria.umsh.features.radio.RadioDetailModel.Battery
import com.voria.umsh.features.radio.RadioDetailModel.Charge
import com.voria.umsh.features.radio.RadioDetailModel.Primary
import com.voria.umsh.features.radio.RadioDetailModel.Status
import com.voria.umsh.services.radio.BoardCatalog
import com.voria.umsh.services.radio.RadioControlState
import com.voria.umsh.services.radio.RadioProblemWords
import com.voria.umsh.services.radio.resolvedArgs
import java.time.Instant
import java.util.Locale

/** The confirmations Radio Detail asks for, kept across a rotation. */
private enum class RadioConfirmation { Forget, Restart, FactoryReset }

/**
 * Radio Detail (`radio-detail.svg` 1–6): the companion radio's board,
 * name, model, state and battery, then Disconnect (or Stop waiting, or
 * Reconnect) and Forget, then the Mesh radio, Connection, Offline
 * assistance, Radio identity and Maintenance sections.
 *
 * Opened from the radio control above the shell, or as Settings' Companion
 * radio, beside the list on a wide window ([inPane]; above the shell it is
 * full width at every size). [onBack] is null beside the list. [onGone] closes the page when there is no radio left to show: after
 * Forget, or after a factory reset the radio accepted.
 *
 * [onChooseRadio] opens Choose a radio (Maintenance › Choose another
 * radio), which is not offered while the staging core holds its radio.
 * Manage device and the radio identity's peer page are left out until the
 * pages they open exist (D14).
 */
@Composable
fun RadioDetailScreen(onBack: (() -> Unit)?, onGone: () -> Unit, inPane: Boolean, onChooseRadio: () -> Unit) {
    val host = LocalAppCoreHost.current
    // The shell's store: the page above the shell and the Settings pane are one ViewModel.
    val viewModel = runtimeViewModel(owner = LocalShellViewModelStoreOwner.current) { RadioDetailViewModel(it, host) }
    val radio by viewModel.radio.collectAsStateWithLifecycle()
    val known by viewModel.radioKnown.collectAsStateWithLifecycle()
    val now by viewModel.now.collectAsStateWithLifecycle()
    val identity by viewModel.identity.collectAsStateWithLifecycle()
    val modelId by viewModel.boundModelId.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val board = remember(modelId) { BoardCatalog.bundled(context).board(modelId) }
    val failure by viewModel.failure.collectAsStateWithLifecycle()
    val stagingRadio by host.stagingRadio.collectAsStateWithLifecycle()
    val resetAccepted by viewModel.resetAccepted.collectAsStateWithLifecycle()
    var confirming by rememberSaveable { mutableStateOf<RadioConfirmation?>(null) }

    val activity = LocalActivity.current
    DisposableEffect(viewModel) {
        viewModel.pageShown()
        onDispose { viewModel.pageLeft(recreating = activity?.isChangingConfigurations == true) }
    }

    val shown = radio
    val gone = known && shown == null
    LaunchedEffect(gone) { if (gone) onGone() }
    LaunchedEffect(resetAccepted) {
        if (resetAccepted) {
            viewModel.resetAcceptedSeen()
            onGone()
        }
    }

    val page: @Composable () -> Unit = {
        UmshScaffold(
            topBar = { UmshTopAppBar(stringResource(R.string.radio_detail_title), onBack = onBack) },
            modifier = Modifier.testTag(Tags.RADIO_DETAIL),
        ) { padding ->
            if (shown == null) return@UmshScaffold
            val model = RadioDetailModel.from(shown, board)
            Box(Modifier.padding(padding).fillMaxWidth(), contentAlignment = Alignment.TopCenter) {
                Column(
                    Modifier
                        .widthIn(max = 600.dp)
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState())
                        .padding(bottom = 24.dp),
                ) {
                    Header(model, now)
                    model.reason?.let { ReasonCard(it) }
                    Buttons(
                        model.primary,
                        onPrimary = {
                            when (model.primary) {
                                Primary.Disconnect, Primary.StopWaiting -> viewModel.disconnect()
                                Primary.Reconnect, Primary.Connect -> viewModel.reconnect()
                            }
                        },
                        onForget = { confirming = RadioConfirmation.Forget },
                    )
                    if (model.status == Status.Waiting) {
                        Text(
                            stringResource(R.string.radio_waiting_caption),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp).testTag(Tags.RADIO_DETAIL_CAPTION),
                        )
                    }
                    model.mesh?.let { mesh ->
                        val preset = viewModel.presets.presetId(mesh)?.let(::presetLabel)
                        MeshSection(mesh, preset?.let { stringResource(it) })
                    }
                    model.radioId?.let { id ->
                        SectionHeader(stringResource(R.string.radio_section_connection))
                        ValueRow(stringResource(R.string.radio_id), tag = Tags.RADIO_DETAIL_RADIO_ID) {
                            Text(identifierAnnotated(id, monospace = true), style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                    model.offline?.let { OfflineSection(it) }
                    val peer = identity
                    if (model.showsIdentity && peer != null) {
                        SectionHeader(stringResource(R.string.radio_section_identity))
                        val names = rememberDisplayNames()
                        // No action until the peer page exists (D14).
                        ListItem(
                            headlineContent = { Text(names.peer(peer), maxLines = 1, overflow = TextOverflow.Ellipsis) },
                            supportingContent = { Text(identifierAnnotated(peer.hint.text)) },
                            leadingContent = { PeerAvatar(peer, describe = false) },
                            colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                            modifier = Modifier.semantics(mergeDescendants = true) {}.testTag(Tags.RADIO_DETAIL_IDENTITY),
                        )
                    }
                    // The staged radio is the staging core's: none other is chosen.
                    val choosable = stagingRadio == null
                    if (choosable || model.offersMaintenance) {
                        SectionHeader(stringResource(R.string.radio_section_maintenance))
                    }
                    if (choosable) {
                        ActionRow(
                            stringResource(R.string.radio_choose_another),
                            MaterialTheme.colorScheme.primary,
                            Tags.RADIO_DETAIL_CHOOSE_ANOTHER,
                            onClick = onChooseRadio,
                        )
                    }
                    if (model.offersMaintenance) {
                        ActionRow(stringResource(R.string.radio_restart), MaterialTheme.colorScheme.primary, Tags.RADIO_DETAIL_RESTART) {
                            confirming = RadioConfirmation.Restart
                        }
                        ActionRow(stringResource(R.string.radio_factory_reset), MaterialTheme.colorScheme.error, Tags.RADIO_DETAIL_FACTORY_RESET) {
                            confirming = RadioConfirmation.FactoryReset
                        }
                    }
                }
            }
        }
    }
    if (inPane) DetailPane(page) else page()

    when (confirming) {
        RadioConfirmation.Forget -> ConfirmDialog(
            title = stringResource(R.string.forget_radio_title),
            body = stringResource(R.string.forget_radio_body),
            confirm = stringResource(R.string.forget_radio_confirm),
            onConfirm = {
                confirming = null
                viewModel.forget()
            },
            onDismiss = { confirming = null },
        )
        RadioConfirmation.Restart -> ConfirmDialog(
            title = stringResource(R.string.restart_radio_title),
            body = stringResource(R.string.restart_radio_body),
            confirm = stringResource(R.string.restart_radio_confirm),
            onConfirm = {
                confirming = null
                viewModel.restart()
            },
            onDismiss = { confirming = null },
        )
        RadioConfirmation.FactoryReset -> ConfirmDialog(
            title = stringResource(R.string.factory_reset_title),
            body = stringResource(R.string.factory_reset_body),
            confirm = stringResource(R.string.factory_reset_confirm),
            onConfirm = {
                confirming = null
                viewModel.factoryReset()
            },
            onDismiss = { confirming = null },
        )
        null -> Unit
    }
    failure?.let { shownFailure ->
        FailureDialog(
            title = stringResource(
                when (shownFailure.request) {
                    RadioRequestFailure.Request.Restart -> R.string.restart_not_sent_title
                    RadioRequestFailure.Request.FactoryReset -> R.string.factory_reset_not_sent_title
                },
            ),
            body = stringResource(R.string.radio_request_not_delivered),
            error = shownFailure.error,
            onDismiss = viewModel::dismissFailure,
        )
    }
}

/** The board, then name, model, state and battery beside it. */
@Composable
private fun Header(model: RadioDetailModel, now: Instant) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
        horizontalArrangement = Arrangement.spacedBy(16.dp),
        verticalAlignment = Alignment.Top,
    ) {
        BoardPhoto(
            model.modelId,
            Modifier.size(width = 88.dp, height = 64.dp).testTag(Tags.RADIO_DETAIL_PHOTO),
            glyphSize = 32.dp,
        )
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                model.name ?: stringResource(R.string.radio_detail_title),
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.testTag(Tags.RADIO_DETAIL_NAME),
            )
            Text(
                model.model ?: stringResource(R.string.unknown_model),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            StateLine(model.status)
            model.battery?.let { BatteryLine(it, now) }
        }
    }
}

@Composable
private fun StateLine(status: Status) {
    val text = stringResource(status.label)
    val dot = when (status) {
        Status.Connected -> UmshColors.fixed.connected
        Status.Failed -> MaterialTheme.colorScheme.error
        else -> null
    }
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        dot?.let { Box(Modifier.size(8.dp).background(it, CircleShape)) }
        // Changes while the page is open, without the reader doing anything.
        Text(
            text,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }.testTag(Tags.RADIO_DETAIL_STATE),
        )
    }
}

@Composable
private fun BatteryLine(battery: Battery, now: Instant) {
    val locale = LocalConfiguration.current.locales[0]
    val (glyph, text) = when (battery) {
        is Battery.Live -> batteryGlyph(RadioControlState.batteryBars(battery.percent)) to when (battery.charge) {
            Charge.Discharging -> stringResource(R.string.radio_battery_discharging, percent(locale, battery.percent))
            Charge.Charging -> stringResource(R.string.radio_battery_charging, percent(locale, battery.percent))
            Charge.ExternalPower -> stringResource(R.string.radio_battery_external_power, percent(locale, battery.percent))
            null -> percent(locale, battery.percent)
        }
        is Battery.ExternalOnly ->
            (if (battery.charging) R.drawable.ic_bolt else R.drawable.ic_power) to stringResource(R.string.radio_external_power)
        is Battery.Last -> batteryGlyph(RadioControlState.batteryBars(battery.percent)) to (
            battery.readAtMs?.let { readAt ->
                stringResource(R.string.radio_last_battery_short, percent(locale, battery.percent), ageText(Instant.ofEpochMilli(readAt), now))
            } ?: percent(locale, battery.percent)
            )
    }
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp),
        modifier = Modifier.testTag(Tags.RADIO_DETAIL_BATTERY),
    ) {
        Icon(
            painterResource(glyph),
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(16.dp),
        )
        Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

/** Why the connection failed, in the error container (`radio-detail.svg` 4). */
@Composable
private fun ReasonCard(problem: com.voria.umsh.core.MobileRadioProblem) {
    val words = RadioProblemWords.of(problem)
    Surface(
        color = MaterialTheme.colorScheme.errorContainer,
        contentColor = MaterialTheme.colorScheme.onErrorContainer,
        shape = MaterialTheme.shapes.large,
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp)
            .semantics(mergeDescendants = true) {}
            .testTag(Tags.RADIO_DETAIL_REASON),
    ) {
        Row(
            Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(painterResource(R.drawable.ic_error), contentDescription = null, modifier = Modifier.size(RadioControlMetrics.Glyph))
            Text(
                stringResource(words.text, *resolvedArgs(LocalResources.current, words.args)),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

/** Side by side; a label too long for its half wraps rather than being cut. */
@Composable
private fun Buttons(primary: Primary, onPrimary: () -> Unit, onForget: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        FilledTonalButton(onClick = onPrimary, modifier = Modifier.weight(1f).testTag(Tags.RADIO_DETAIL_PRIMARY)) {
            Text(
                stringResource(
                    when (primary) {
                        Primary.Disconnect -> R.string.radio_disconnect
                        Primary.StopWaiting -> R.string.radio_stop_waiting
                        Primary.Reconnect -> R.string.radio_reconnect
                        Primary.Connect -> R.string.radio_connect
                    },
                ),
                textAlign = TextAlign.Center,
            )
        }
        FilledTonalButton(onClick = onForget, modifier = Modifier.weight(1f).testTag(Tags.RADIO_DETAIL_FORGET)) {
            Text(stringResource(R.string.radio_forget), textAlign = TextAlign.Center)
        }
    }
}

@Composable
private fun MeshSection(mesh: RadioDetailModel.Mesh, presetName: String?) {
    val locale = LocalConfiguration.current.locales[0]
    SectionHeader(stringResource(R.string.radio_section_mesh), Modifier.testTag(Tags.RADIO_DETAIL_MESH))
    val summary = phySummary(mesh, locale)
    ListItem(
        headlineContent = { Text(presetName ?: summary) },
        supportingContent = presetName?.let { { Text(summary) } },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
    )
    if (mesh.dutyCycleLimit != null || mesh.dutyCycleNow != null) {
        ValueRow(
            stringResource(R.string.radio_transmit_limit),
            supporting = mesh.dutyCycleNow?.let { stringResource(R.string.radio_transmit_used, dutyText(locale, it)) },
        ) {
            mesh.dutyCycleLimit?.let { limit ->
                Text(
                    if (limit == RadioDetailModel.NO_LIMIT) stringResource(R.string.radio_transmit_limit_none) else dutyText(locale, limit),
                )
            }
        }
    }
    mesh.saved?.let { saved ->
        ValueRow(stringResource(R.string.radio_saved_for_restart)) {
            Text(
                stringResource(
                    when (saved) {
                        SavedSnapshotRecord.NONE -> R.string.radio_saved_no
                        SavedSnapshotRecord.CURRENT -> R.string.radio_saved_yes
                        SavedSnapshotRecord.FALLBACK -> R.string.radio_saved_fallback
                        SavedSnapshotRecord.UNREADABLE -> R.string.radio_saved_unreadable
                        SavedSnapshotRecord.PARTIAL -> R.string.radio_saved_partial
                    },
                ),
            )
        }
    }
}

@Composable
private fun OfflineSection(offline: RadioDetailModel.Offline) {
    val locale = LocalConfiguration.current.locales[0]
    val integers = NumberFormat.getIntegerInstance(locale)
    SectionHeader(stringResource(R.string.radio_section_offline), Modifier.testTag(Tags.RADIO_DETAIL_OFFLINE))
    val counts = listOf(
        R.string.radio_receive_filters to offline.receiveFilters,
        R.string.radio_channel_keys to offline.channelKeys,
        R.string.radio_peer_keys to offline.peerKeys,
        R.string.radio_queued_frames to offline.queuedFrames?.toLong(),
        R.string.radio_dropped_frames to offline.droppedFrames,
    )
    counts.forEach { (label, count) ->
        count?.let { ValueRow(stringResource(label)) { Text(integers.format(it)) } }
    }
    offline.delegatedAcks?.let { on ->
        ValueRow(stringResource(R.string.radio_delegated_acks)) {
            Text(stringResource(if (on) R.string.radio_value_on else R.string.radio_value_off))
        }
    }
}

/** A label, an optional line under it, and its value at the end. */
@Composable
private fun ValueRow(
    label: String,
    supporting: String? = null,
    tag: String? = null,
    value: @Composable () -> Unit,
) {
    ListItem(
        headlineContent = { Text(label) },
        supportingContent = supporting?.let { { Text(it) } },
        trailingContent = value,
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier.semantics(mergeDescendants = true) {}.let { if (tag != null) it.testTag(tag) else it },
    )
}

/** A Maintenance row: a verb in [color], which opens its confirmation or page. */
@Composable
private fun ActionRow(label: String, color: Color, tag: String, onClick: () -> Unit) {
    ListItem(
        headlineContent = { Text(label, color = color) },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier.clickable(role = Role.Button, onClick = onClick).testTag(tag),
    )
}

private fun percent(locale: Locale, percent: Int): String =
    NumberFormat.getPercentInstance(locale).format(percent / 100.0)

/** A fraction of the hour out of 65535, as a percentage: two decimals below 1%, else at most one. */
private fun dutyText(locale: Locale, value: Int): String {
    val fraction = value / RadioDetailModel.NO_LIMIT.toDouble()
    val format = NumberFormat.getPercentInstance(locale).apply {
        maximumFractionDigits = if (fraction < 0.01) 2 else 1
    }
    return format.format(fraction)
}

@Composable
private fun phySummary(mesh: RadioDetailModel.Mesh, locale: Locale): String {
    val measures = MeasureFormat.getInstance(locale, MeasureFormat.FormatWidth.SHORT)
    val integers = NumberFormat.getIntegerInstance(locale)
    val frequency = measures.format(Measure(mesh.frequencyKhz / 1_000.0, MeasureUnit.MEGAHERTZ))
    val power = integers.format(mesh.transmitPowerDbm.toLong())
    val bandwidth = mesh.bandwidthHz
    val sf = mesh.spreadingFactor
    val cr = mesh.codingRateDenominator
    if (bandwidth == null || sf == null || cr == null) {
        return stringResource(R.string.radio_phy_summary_short, frequency, power)
    }
    return stringResource(
        R.string.radio_phy_summary,
        frequency,
        measures.format(Measure(bandwidth / 1_000.0, MeasureUnit.KILOHERTZ)),
        integers.format(sf.toLong()),
        integers.format(cr.toLong()),
        power,
    )
}
